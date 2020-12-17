<#
.Synopsis
   Automatically download scans from the My Scans folder (or custom folder) and move them to a different folder of your choosing for archival purposes.
.DESCRIPTION
   This script is useful for automating the downloads of Nessus scan files. The script will be able to allow for some customizations
   such as the Nessus scanner host, the location of the downloads, and the Nessus scan folder for which you wish to move the scans
   after they have been downloaded. This tool was inspired from the Posh-Nessus script. Due to lack of updates on the Posh-Nessus
   project, it seemed easeier to call the raw API to perform the bare minimum functions necessary to export
   scans out automatically. I appreciate Tenable leaving these core API functions (export scan and scan status) in their product.

   Tested for Nessus 8.9.0+.

.EXAMPLE
   .\ExtractFrom-Nessus.ps1 -NessusHostNameOrIP "127.0.0.1" -Port "8834" -DownloadFileLocation "C:\Nessus" -AccessKey "redacted" -SecretKey "redacted" -SourceFolderName "My Scans" -ArchiveFolderName "Archive-Ingested" -ExtendedFileNameAttribute "-scanner1"
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
    [Parameter(Mandatory=$false,
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
    $DownloadFileLocation,
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
    # The source folder for where the Nessus scans live in the UI. The Default is "My Scans
    [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=5)]
    $SourceFolderName,
    # The destintation folder in Nessus UI for where you wish to move your scans for archive.
        [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=6)]
    $ArchiveFolderName,
    # Added atrribute for the end of the file name for uniqueness when using with multiple scanners
    [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=7)]
    $ExtendedFileNameAttribute
)

Begin{
    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    $headers =  @{'X-ApiKeys' = "accessKey=$AccessKey; secretKey=$SecretKey"}
    #Don't parse the file downloads because we care about speed!
    $ProgressPreference = 'SilentlyContinue'

    #Get FolderID from Folder name
    function getFolderIdFromName {
        param (
            $folderNames
        )
        $folders = Invoke-RestMethod -Method Get -Uri "https://$($NessusHostNameOrIP)/folders" -ContentType "application/json" -Headers $headers
        Write-Host "Folders Found: "
        $folders.folders.Name | ForEach-Object{
            Write-Host "$_" -ForegroundColor Green
        }
        $global:sourceFolderId = $($folders.folders | Where-Object {$_.Name -eq $folderNames[0]}).id
        $global:archiveFolderId = $($folders.folders | Where-Object {$_.Name -eq $folderNames[1]}).id
    }
    getFolderIdFromName $SourceFolderName, $ArchiveFolderName
    
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
    function sleep15Minutes{
        $sleeps = "Scans not finished, going to sleep for 15 minutes. " + $(Get-Date)
        Write-Host $sleeps
        Start-Sleep -s 900
    }

    #Update Scan status
    function updateStatus{
        #Store the current Nessus Scans and their completing/running status to currentNessusScanData
        $global:currentNessusScanDataRaw = Invoke-RestMethod -Method Get -Uri "https://$($NessusHostNameOrIP)/scans?folder_id=$($global:sourceFolderId)" -ContentType "application/json" -Headers $headers
        $global:listOfScans = $global:currentNessusScanDataRaw.scans | Select-Object -Property Name,Status,creation_date,id
        If($global:listOfScans){Write-Host "Scans found!" -ForegroundColor Green; $global:listOfScans}else{Write-Host "No scans found." -ForegroundColor Red}
    }

    function getScanIdsAndExport{
        updateStatus
        $global:listOfScans | ForEach-Object {
            Write-Host "Going to export $($_.name)"
            export($_.id)
            Write-Host "Finished export of $($_.name), going to update status..."
        }
    }

    function Move-ScanToArchive{
        $body = [PSCustomObject]@{
            folder_id = $archiveFolderId
        } | ConvertTo-Json
        $ScanDetails = Invoke-RestMethod -Method Put -Uri "https://$($NessusHostNameOrIP)/scans/$($scanId)/folder" -Body $body -ContentType "application/json" -Headers $headers
        Write-Host $ScanDetails -ForegroundColor Red
        Write-Host "Scan Moved to Archive - Export Complete." -ForegroundColor Green
    }

    function export{
        Param($scanId)
        Write-Host $scanId
        do{
            $convertedTime = convertToISO($($global:currentNessusScanDataRaw.scans | Where-Object {$_.id -eq $scanId}).creation_date)
            $exportFileName = $DownloadFileLocation+$($convertedTime | Get-Date -Format yyyy_MM_dd).ToString() + "-$scanId$($ExtendedFileNameAttribute).nessus"
            $exportComplete = 0
            $currentScanIdStatus = $($global:currentNessusScanDataRaw.scans | Where-Object {$_.id -eq $scanId}).status
			#Check to see if scan is not running or is an empty scan, if true then lets export!
			if($currentScanIdStatus -ne 'running' -or $currentScanIdStatus -ne 'empty'){
                try
                {
                    $scanExportOptions = [PSCustomObject]@{
                        "format" = "nessus"
                    } | ConvertTo-Json
                    #Start the export process to Nessus has the file prepared for download
                    $exportInfo = Invoke-RestMethod -Method Post "https://$($NessusHostNameOrIP)/scans/$($scanId)/export" -Body $scanExportOptions -ContentType "application/json" -Headers $headers
                    $exportStatus = ''
                    while ($exportStatus.status -ne 'ready')
                    {
                        try
                        {
                            $exportStatus = Invoke-RestMethod -Method Get "https://$($NessusHostNameOrIP)/scans/$($ScanId)/export/$($exportInfo.file)/status" -ContentType "application/json" -Headers $headers
                            Write-Host "Export status: $($exportStatus.status)"
                        }
                        catch
                        {
                            Write-Host "An error has occurred while trying to export the scan"
                            break
                        }
                        Start-Sleep -Seconds 1
                    }
                    #Time to download the Nessus scan!
                    Invoke-RestMethod -Method Get -Uri "https://$($NessusHostNameOrIP)/scans/$($scanId)/export/$($exportInfo.file)/download" -ContentType "application/json" -Headers $headers -OutFile $exportFileName
                    $exportComplete = 1
                    Write-Host "Export succeeded!" -ForegroundColor Green
                    #Move scan to archive!
                    Move-ScanToArchive
                }
                catch [System.Net.WebException]
                {
                    Write-Host 'Nessus Struggles to Export a Scan, exiting.'
                    exit
                }
            }
            #If a scan is empty because it hasn't been started skip the export and move on.
            if ($currentScanIdStatus -eq 'empty') {
                Write-Host "Scan has not been started, therefore skipping this scan."
                $exportComplete = 2
            }
            if($exportComplete -eq 0){
                sleep15Minutes
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
    } While ($x -gt 2)
}

End{
    Write-Host "Finished Exporting!" -ForegroundColor White
    #Kick of the Nessus Import! Just uncomment the two lines below and provide valid parameters.
    #Write-Host "Time to ingest! Kicking off the Automate-NessusImport.ps1 script to ingest this data into Elasticsearch!"
    #.\Automate-NessusImport.ps1 -DownloadedNessusFileLocation $DownloadFileLocation -ElasticsearchURL "http://127.0.0.1:9200" -IndexName "nessus" -ElasticsearchApiKey "redacted"
}
