<#
.Synopsis
   Automatically download scans from the My Scans folder (or custom folder) and move them to a different folder of your choosing for archival purposes (if you so choose).
   Supplying Elasticsearch variables to this script will kick off the automation necessary to ingest the Nessus data into Elasticsearch. 
   (Requires AutomateNessus.ps1 and ImportTo-Elasticsearch-Nessus.ps1 for end to end automation)
.DESCRIPTION
   This script is useful for automating the downloads of Nessus scan files. The script will be able to allow for some customizations
   such as the Nessus scanner host, the location of the downloads, and the Nessus scan folder for which you wish to move the scans
   after they have been downloaded (if you so choose). This tool was inspired from the Posh-Nessus script. Due to lack of updates on the Posh-Nessus
   project, it seemed easeier to call the raw API to perform the bare minimum functions necessary to export
   scans out automatically. I appreciate Tenable leaving these core API functions (export scan and scan status) in their product.

   Tested for Nessus 8.9.0+.

.EXAMPLE
   .\ExtractFrom-Nessus.ps1 -NessusHostNameOrIP "127.0.0.1" -Port "8834" -DownloadedNessusFileLocation "C:\Nessus" -AccessKey "redacted" -SecretKey "redacted" -SourceFolderName "My Scans" -ArchiveFolderName "Archive-Ingested" -ExtendedFileNameAttribute "_scanner1" -ElasticsearchURL "http://127.0.0.1:9200" -IndexName "logs-nessus.vulnerability" -ElasticsearchApiKey "redacted" -ExportScansFromToday "false" -ExportDay "01/11/2021"
#>

[CmdletBinding()]
[Alias()]
Param
(
    # Nessus Host Name or IP Address
    [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
    $NessusHostNameOrIP,
    # Port that Nessus is listening on
    [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
    $Port,
    # The location where you wish to save the extracted Nessus files from the scanner
    [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
    $DownloadedNessusFileLocation,
    # Nessus Access Key
    [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=3)]
    $AccessKey,
    # Nessus Secret Key
    [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=4)]
    $SecretKey,
    # The source folder for where the Nessus scans live in the UI. The Default is "My Scans"
    [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        Position=5)]
    $SourceFolderName,
    # The destintation folder in Nessus UI for where you wish to move your scans for archive. If this is not configued, scans will not be moved after download.
        [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        Position=6)]
    $ArchiveFolderName,
    # Added atrribute for the end of the file name for uniqueness when using with multiple scanners
    [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        Position=7)]
    $ExtendedFileNameAttribute,
    # Add Elasticsearch Host to automate Nessus import
    [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=8)]
    $ElasticsearchURL,
    # Add Elasticsearch index name to automate Nessus import
    [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=9)]
    $IndexName,
    # Add Elasticsearch API key to automate Nessus import
    [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=10)]
    $ElasticsearchApiKey,
    # Use this setting if you wish to only export the scans on the day the scan occurred. Default value is false.
    [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        Position=11)]
    $ExportScansFromToday,
    # Use this setting if you want to export scans for the specific day that the scan or scans occurred.
    [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        Position=12)]
    $ExportDay
)

Begin{
    if($PSVersionTable.PSVersion.Major -ge 7){
        Write-Host "PowerShell version $($PSVersionTable.PSVersion.Major) detected, great!"
    }else{
        Write-Host "Old version of PowerShell detected $($PSVersionTable.PSVersion.Major). Please install PowerShell 7+. Exiting."Write-Host "No scans found." -ForegroundColor Red
        Exit
    }
    
    $NessusURLandPort = $NessusHostNameOrIP+":"+$port
    $headers =  @{'X-ApiKeys' = "accessKey=$AccessKey; secretKey=$SecretKey"}
    #Don't parse the file downloads because we care about speed!
    $ProgressPreference = 'SilentlyContinue'
    if($null -eq $SourceFolderName ){
        $SourceFolderName = "My Scans"
    }

    #Check to see if export scan directory exists, if not, create it!
    if($(Test-Path -Path $DownloadedNessusFileLocation) -eq $false){
        Write-Host "Could not find $DownloadedNessusFileLocation so creating that directory now."
        New-Item $DownloadedNessusFileLocation -ItemType Directory
    }

    #Get FolderID from Folder name
    function getFolderIdFromName {
        param (
            $folderNames
        )

        $folders = Invoke-RestMethod -Method Get -Uri "https://$NessusURLandPort/folders" -ContentType "application/json" -Headers $headers -SkipCertificateCheck
        Write-Host "Folders Found: "
        $folders.folders.Name | ForEach-Object{
            Write-Host "$_" -ForegroundColor Green
        }
        $global:sourceFolderId = $($folders.folders | Where-Object {$_.Name -eq $folderNames[0]}).id
        $global:archiveFolderId = $($folders.folders | Where-Object {$_.Name -eq $folderNames[1]}).id
    }
    getFolderIdFromName $SourceFolderName, $ArchiveFolderName

    #Hardcoded Elasticsearch variables
    #$ElasticsearchURL = "http://127.0.0.1:9200"
    #$IndexName = "logs-nessus.vulnerability" 
    #$ElasticsearchApiKey = ""

}

Process{
    #Simple epoch to ISO8601 Timestamp converter
    function convertToISO {
        Param($epochTime)
        [datetime]$epoch = '1970-01-01 00:00:00'
        [datetime]$result = $epoch.AddSeconds($epochTime)
        $newTime = Get-Date $result -Format "o"
        return $newTime
    }

    #Sleep if scans are not finished
    function sleep5Minutes{
        $sleeps = "Scans not finished, going to sleep for 5 minutes. " + $(Get-Date)
        Write-Host $sleeps
        Start-Sleep -s 300
    }

    #Update Scan status
    function updateStatus{
        #Store the current Nessus Scans and their completing/running status to currentNessusScanData
        $global:currentNessusScanDataRaw = Invoke-RestMethod -Method Get -Uri "https://$NessusURLandPort/scans?folder_id=$($global:sourceFolderId)" -ContentType "application/json" -Headers $headers -SkipCertificateCheck
        $global:listOfScans = $global:currentNessusScanDataRaw.scans | Select-Object -Property Name,Status,creation_date,id
        if($global:listOfScans){
            Write-Host "Scans found!" -ForegroundColor Green
            $global:listOfScans
        }else{
            Write-Host "No scans found." -ForegroundColor Red
        }
    }

    function getScanIdsAndExport{
        updateStatus
        if($ExportScansFromToday -eq "true"){
            #Gets current day
            $getdate = Get-Date -Format "dddd-d"
            $global:listOfScans | ForEach-Object {
                if($(convertToISO($_.creation_date) | Get-Date -format "dddd-d") -eq $getDate){
                    Write-Host "Going to export $_"
                    export($_.id)
                    Write-Host "Finished export of $_, going to update status..."
                }
            }
        }elseif($null -ne $ExportDay){
            #Gets day entered from arguments
            $getDate = $ExportDay | Get-Date -Format "dddd-d"
            $global:listOfScans | ForEach-Object {
                if($(convertToISO($_.creation_date) | Get-Date -format "dddd-d") -eq $getDate){
                    Write-Host "Going to export $_"
                    export($_.id)
                    Write-Host "Finished export of $_, going to update status..."
                }else{
                    Write-Host $_
                    Write-Host convertToISO($_.creation_date)
                }
            }
        }else{
            $global:listOfScans | ForEach-Object {
                Write-Host "Going to export $($_.name)"
                export($_.id)
                Write-Host "Finished export of $($_.name), going to update status..."
            }
        }
    }

    function Move-ScanToArchive{
        $body = [PSCustomObject]@{
            folder_id = $archiveFolderId
        } | ConvertTo-Json

        $ScanDetails = Invoke-RestMethod -Method Put -Uri "https://$NessusURLandPort/scans/$($scanId)/folder" -Body $body -ContentType "application/json" -Headers $headers -SkipCertificateCheck
        Write-Host $ScanDetails -ForegroundColor Yellow
        Write-Host "Scan Moved to Archive - Export Complete." -ForegroundColor Green
    }

    function export{
        Param($scanId)
        Write-Host $scanId
        do{
            $convertedTime = convertToISO($($global:currentNessusScanDataRaw.scans | Where-Object {$_.id -eq $scanId}).creation_date)
            $exportFileName = Join-Path $DownloadedNessusFileLocation $($($convertedTime | Get-Date -Format yyyy_MM_dd).ToString()+"-$scanId$($ExtendedFileNameAttribute).nessus")
            $exportComplete = 0
            $currentScanIdStatus = $($global:currentNessusScanDataRaw.scans | Where-Object {$_.id -eq $scanId}).status
			#Check to see if scan is not running or is an empty scan, if true then lets export!
			if($currentScanIdStatus -ne 'running' -and $currentScanIdStatus -ne 'empty'){
                $scanExportOptions = [PSCustomObject]@{
                    "format" = "nessus"
                } | ConvertTo-Json
                #Start the export process to Nessus has the file prepared for download
                $exportInfo = Invoke-RestMethod -Method Post "https://$NessusURLandPort/scans/$($scanId)/export" -Body $scanExportOptions -ContentType "application/json" -Headers $headers -SkipCertificateCheck
                $exportStatus = ''
                while ($exportStatus.status -ne 'ready') {
                    try {
                        $exportStatus = Invoke-RestMethod -Method Get "https://$NessusURLandPort/scans/$($ScanId)/export/$($exportInfo.file)/status" -ContentType "application/json" -Headers $headers -SkipCertificateCheck
                        Write-Host "Export status: $($exportStatus.status)"
                    }
                    catch {
                        Write-Host "An error has occurred while trying to export the scan"
                        break
                    }
                    Start-Sleep -Seconds 1
                }
                #Time to download the Nessus scan!
                Invoke-RestMethod -Method Get -Uri "https://$NessusURLandPort/scans/$($scanId)/export/$($exportInfo.file)/download" -ContentType "application/json" -Headers $headers -OutFile $exportFileName -SkipCertificateCheck
                $exportComplete = 1
                Write-Host "Export succeeded!" -ForegroundColor Green
                if($null -ne $ArchiveFolderName){
                    #Move scan to archive if folder is configured!
                    Write-Host "Archive scan folder configured so going to move the scan in the Nessus web UI to $ArchiveFolderName" -Foreground Yellow
                    Move-ScanToArchive
                }else{
                    Write-Host "Archive folder not configured so not moving scan in the Nessus web UI." -Foreground Yellow
                }

            }
            #If a scan is empty because it hasn't been started skip the export and move on.
            if ($currentScanIdStatus -eq 'empty') {
                Write-Host "Scan has not been started, therefore skipping this scan."
                $exportComplete = 2
            }
            if($exportComplete -eq 0){
                sleep5Minutes
                updateStatus
            }
        } While ($exportComplete -eq 0)

    }

    $x = 3
    do{
        getScanIdsAndExport
        #Stop Nessus to get a fresh start
        if ($global:currentNessusScanData.Status -notcontains 'running'){
        }else{
            Write-Host 'Nessus has issues, investigate now!'
        }
        $x = 1
    } while ($x -gt 2)
}

End{
    Write-Host "Finished Exporting!" -ForegroundColor White
    #Kick of the Nessus Import! Just uncomment the two lines below and provide valid parameters.
    if(($null -ne $DownloadedNessusFileLocation) -and ($null -ne $ElasticsearchURL) -and ($null -ne $IndexName) -and ($null -ne $ElasticsearchApiKey)){
        Write-Host "All Elasticsearch variables configured!" -Foreground Green
	    Write-Host "Time to ingest! Kicking off the Automate-NessusImport.ps1 script to ingest this data into Elasticsearch!"    
        & $(Resolve-Path Automate-NessusImport.ps1).path -DownloadedNessusFileLocation $DownloadedNessusFileLocation -ElasticsearchURL $ElasticsearchURL -IndexName $IndexName -ElasticsearchApiKey $ElasticsearchApiKey
    }else{
    	Write-Host "Not all of the Elasticsearch variables were configured to kick off the Automate-NessusImport script. This is the end of this process." -Foreground Yellow
    }
}
