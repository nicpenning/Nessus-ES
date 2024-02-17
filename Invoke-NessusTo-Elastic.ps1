<#
.Synopsis
    This script is a combination of extracting, importing, and automating Nessus scan data into the Elastic stack.
    
    *Invoke-Exract_From_Nessus*
    Downloads scans from the My Scans folder (or custom folder) and move them to a different folder of your choosing for archival purposes.

    *Invoke-Import_Nessus_To_Elasticsearch*
    Parses a single Nessus XML report and imports it into Elasticsearch using the _bulk API.

    *Invoke-Automate_Nessus_File_Imports*
    Automatically checks for any unprocessed .nessus files and ingest them into Elastic.

    *Setup-Elastic-Stack*
    Use this script to configure an Elastic stack to properly ingest and visualize the Nessus scan data before ingestion.

.DESCRIPTION
   This script is useful for automating the downloads of Nessus scan files and importing them into the Elastic stack. The script will be able to allow for some customizations
   such as the Nessus scanner host, the location of the downloads, and the Nessus scan folder for which you wish to move the scans
   after they have been downloaded (if you so choose). This tool was inspired from the Posh-Nessus script. Due to lack of updates on the Posh-Nessus
   project, it seemed easier to call the raw API to perform the bare minimum functions necessary to export
   scans out automatically. I appreciate Tenable leaving these core API functions (export scan and scan status) in their product.

   Tested for Nessus 8.9.0+, Latest Tested 10.7.0.

   Variable Options
   -Nessus_URL "https://127.0.0.1:8834"
   -Nessus_File_Download_Location "C:\Nessus"
   -Nessus_Access_Key "redacted"
   -Nessus_Secret_Key "redacted"
   -Nessus_Source_Folder_Name "My Scans"
   -Nessus_Archive_Folder_Name "Archive-Ingested"
   -Export_Scans_From_Today "false"
   -Export_Day "01/11/2021"
   -Export_Custom_Extended_File_Name_Attribute "_scanner1"
   -Elasticsearch_URL "http://127.0.0.1:9200"
   -Elasticsearch_Index_Name "logs-nessus.vulnerability"
   -Elasticsearch_Api_Key "redacted"

.EXAMPLE
   .\Invoke-NessusTo-Elastic.ps1 -Nessus_URL "https://127.0.0.1:8834" -Nessus_File_Download_Location "C:\Nessus" -Nessus_Access_Key "redacted" -Nessus_Secret_Key "redacted" -Nessus_Source_Folder_Name "My Scans" -Nessus_Archive_Folder_Name "Archive-Ingested" -Export_Scans_From_Today "false" -Export_Day "01/11/2021" -Export_Custom_Extended_File_Name_Attribute "_scanner1" -Elasticsearch_URL "http://127.0.0.1:9200" -Elasticsearch_Index_Name "logs-nessus.vulnerability" -Elasticsearch_Api_Key "redacted"
#>

Param (
    # Nessus URL. (default - https://127.0.0.1:8834)
    [Parameter(Mandatory=$false)]
    $Nessus_URL = "https://127.0.0.1:8834",
    # The location where you wish to save the extracted Nessus files from the scanner (default - Nessus_Exports)
    [Parameter(Mandatory=$false)]
    $Nessus_File_Download_Location = "Nessus_Exports",
    # The location of a specifc Nessus file for processing.
    [Parameter(Mandatory=$false)]
    $Nessus_XML_File,
    # Nessus Access Key
    [Parameter(Mandatory=$false)]
    $Nessus_Access_Key = $null,
    # Nessus Secret Key
    [Parameter(Mandatory=$false)]
    $Nessus_Secret_Key = $null,
    # The source folder for where the Nessus scans live in the UI. (default - "My Scans")
    [Parameter(Mandatory=$false)]
    $Nessus_Source_Folder_Name = "My Scans",
    # The destination folder in Nessus UI for where you wish to move your scans for archive. (default - none - scans won't move)
    [Parameter(Mandatory=$false)]
    $Nessus_Archive_Folder_Name = $null,
    # The scan name you want to delete the older scan from (default - none - scans won't get deleted)
    [Parameter(Mandatory=$false)]
    $Nessus_Scan_Name_To_Delete_Oldest_Scan = $null,
    # Use this setting if you wish to only export the scans on the day the scan occurred. (default - false)
    [Parameter(Mandatory=$false)]
    $Export_Scans_From_Today = $null,
    # Use this setting if you want to export scans for the specific day that the scan or scans occurred. (example - 11/07/2023)
    [Parameter(Mandatory=$false)]
    $Export_Day = $null,
    # Added atrribute for the end of the file name for uniqueness when using with multiple scanners. (example - _scanner1)
    [Parameter(Mandatory=$false)]
    $Export_Custom_Extended_File_Name_Attribute = $null,
    # Add Elasticsearch URL to automate Nessus import (default - https://127.0.0.1:9200)
    [Parameter(Mandatory=$false)]
    $Elasticsearch_URL = "https://127.0.0.1:9200",
    # Add Elasticsearch index name to automate Nessus import (default - logs-nessus.vulnerability)
    [Parameter(Mandatory=$false)]
    $Elasticsearch_Index_Name = "logs-nessus.vulnerability",
    # Add Elasticsearch API key to automate Nessus import
    [Parameter(Mandatory=$false)]
    $Elasticsearch_Api_Key = $null,
    # Selected option for automation
    [Parameter(Mandatory=$false)]
    $Option_Selected
)

Begin{
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        Write-Host "PowerShell version $($PSVersionTable.PSVersion.Major) detected, great!"
    } else {
        Write-Host "Old version of PowerShell detected $($PSVersionTable.PSVersion.Major). Please install PowerShell 7+. Exiting."Write-Host "No scans found." -ForegroundColor Red
        Exit
    }

    $option0 = "0. Setup Elasticsearch and Kibana."
    $option1 = "1. Export Nessus files."
    $option2 = "2. Ingest a single Nessus file into Elasticsearch."
    $option3 = "3. Ingest all Nessus files from a specified directory into Elasticsearch."
    $option4 = "4. Export and Ingest Nessus files into Elasticsearch."
    $option5 = "5. Purge processed hashes list (remove list of what files have already been processed)."
    #$option10 = "10. Delete oldest scan from scan history (Future / Only works with Nessus Manager license)"
    $quit = "Q. Quit"
    $version = "`nVersion 0.8.1"

    function Show-Menu {
        Write-Host "Welcome to the PowerShell script that can export and ingest Nessus scan files into an Elastic stack!" -ForegroundColor Blue
        Write-Host "What would you like to do?" -ForegroundColor Yellow
        Write-Host $option0
        Write-Host $option1
        Write-Host $option2
        Write-Host $option3
        Write-Host $option4
        Write-Host $option5
        Write-Host $option10
        Write-Host $quit
        Write-Host $version
    }
    
    # Miscellenous Functions
    # Get FolderID from Folder name
    function getFolderIdFromName {
        param ($folderNames)

        $folders = Invoke-RestMethod -Method Get -Uri "$Nessus_URL/folders" -ContentType "application/json" -Headers $headers -SkipCertificateCheck
        Write-Host "Folders Found: "
        $folders.folders.Name | ForEach-Object {
            Write-Host "$_" -ForegroundColor Green
        }
        $global:sourceFolderId = $($folders.folders | Where-Object {$_.Name -eq $folderNames[0]}).id
        $global:archiveFolderId = $($folders.folders | Where-Object {$_.Name -eq $folderNames[1]}).id
    }

    # Update Scan status
    function updateStatus {
        #Store the current Nessus Scans and their completing/running status to currentNessusScanData
        $global:currentNessusScanDataRaw = Invoke-RestMethod -Method Get -Uri "$Nessus_URL/scans?folder_id=$($global:sourceFolderId)" -ContentType "application/json" -Headers $headers -SkipCertificateCheck
        $global:listOfScans = $global:currentNessusScanDataRaw.scans | Select-Object -Property Name,Status,creation_date,id
        if ($global:listOfScans) {
            Write-Host "Scans found!" -ForegroundColor Green
            $global:listOfScans
        } else {
            Write-Host "No scans found." -ForegroundColor Red
        }
    }
    
    # Simple epoch to ISO8601 Timestamp converter
    function convertToISO {
        Param($epochTime)
        [datetime]$epoch = '1970-01-01 00:00:00'
        [datetime]$result = $epoch.AddSeconds($epochTime)
        $newTime = Get-Date $result -Format "o"
        return $newTime
    }

    # Core Functions
    function Invoke-Exract_From_Nessus {
        Param (
            # Nessus URL. (default - https://127.0.0.1:8834)
            [Parameter(Mandatory=$false)]
            $Nessus_URL,
            # The location where you wish to save the extracted Nessus files from the scanner. (default - Nessus_Exports)
            [Parameter(Mandatory=$false)]
            $Nessus_File_Download_Location,
            # Nessus Access Key
            [Parameter(Mandatory=$true)]
            $Nessus_Access_Key,
            # Nessus Secret Key
            [Parameter(Mandatory=$true)]
            $Nessus_Secret_Key,
            # The source folder for where the Nessus scans live in the UI. (default - "My Scans")
            [Parameter(Mandatory=$false)]
            $Nessus_Source_Folder_Name,
            # The destination folder in Nessus UI for where you wish to move your scans for archive. (default - none - scans won't move)
            [Parameter(Mandatory=$false)]
            $Nessus_Archive_Folder_Name,
            # Use this setting if you wish to only export the scans on the day the scan occurred. (default - false)
            [Parameter(Mandatory=$false)]
            $Export_Scans_From_Today,
            # Use this setting if you want to export scans for the specific day that the scan or scans occurred. (example - 11/07/2023)
            [Parameter(Mandatory=$false)]
            $Export_Day,
            # Added atrribute for the end of the file name for uniqueness when using with multiple scanners. (example - _scanner1)
            [Parameter(Mandatory=$false)]
            $Export_Custom_Extended_File_Name_Attribute
        )
#>
        $headers =  @{'X-ApiKeys' = "accessKey=$Nessus_Access_Key; secretKey=$Nessus_Secret_Key"}
        #Don't parse the file downloads because we care about speed!
        $ProgressPreference = 'SilentlyContinue'

        #Check to see if export scan directory exists, if not, create it!
        if ($(Test-Path -Path $Nessus_File_Download_Location) -eq $false) {
            Write-Host "Could not find $Nessus_File_Download_Location so creating that directory now."
            New-Item $Nessus_File_Download_Location -ItemType Directory
        }

        #Get FolderID from Folder name
        function getFolderIdFromName {
            param ($folderNames)

            $folders = Invoke-RestMethod -Method Get -Uri "$Nessus_URL/folders" -ContentType "application/json" -Headers $headers -SkipCertificateCheck
            Write-Host "Folders Found: "
            $folders.folders.Name | ForEach-Object {
                Write-Host "$_" -ForegroundColor Green
            }
            $global:sourceFolderId = $($folders.folders | Where-Object {$_.Name -eq $folderNames[0]}).id
            $global:archiveFolderId = $($folders.folders | Where-Object {$_.Name -eq $folderNames[1]}).id
        }
        getFolderIdFromName $Nessus_Source_Folder_Name, $Nessus_Archive_Folder_Name

        #Simple epoch to ISO8601 Timestamp converter
        function convertToISO {
            Param($epochTime)
            [datetime]$epoch = '1970-01-01 00:00:00'
            [datetime]$result = $epoch.AddSeconds($epochTime)
            $newTime = Get-Date $result -Format "o"
            return $newTime
        }

        #Sleep if scans are not finished
        function sleep5Minutes {
            $sleeps = "Scans not finished, going to sleep for 5 minutes. " + $(Get-Date)
            Write-Host $sleeps
            Start-Sleep -s 300
        }

        #Update Scan status
        function updateStatus {
            #Store the current Nessus Scans and their completing/running status to currentNessusScanData
            $global:currentNessusScanDataRaw = Invoke-RestMethod -Method Get -Uri "$Nessus_URL/scans?folder_id=$($global:sourceFolderId)" -ContentType "application/json" -Headers $headers -SkipCertificateCheck
            $global:listOfScans = $global:currentNessusScanDataRaw.scans | Select-Object -Property Name,Status,creation_date,id
            if ($global:listOfScans) {
                Write-Host "Scans found!" -ForegroundColor Green
                $global:listOfScans
            } else {
                Write-Host "No scans found." -ForegroundColor Red
            }
        }

        function getScanIdsAndExport{
            updateStatus
            if ($Export_Scans_From_Today -eq "true") {
                #Gets current day
                $getDate = Get-Date -Format "dddd-d"
                $global:listOfScans | ForEach-Object {
                    if ($(convertToISO($_.creation_date) | Get-Date -format "dddd-d") -eq $getDate) {
                        Write-Host "Going to export $_"
                        export -scanId $($_.id) -scanName $($_.name)
                        Write-Host "Finished export of $_, going to update status..."
                    }
                }
            } elseif ($null -ne $Export_Day) {
                #Gets day entered from arguments
                $getDate = $Export_Day | Get-Date -Format "dddd-d"
                $global:listOfScans | ForEach-Object {
                    $currentId = $_.id
                    $scanName = $_.name
                    $scanHistory = Invoke-RestMethod -Method Get -Uri "$Nessus_URL/scans/$($currentId)?limit=2500" -ContentType "application/json" -Headers $headers -SkipCertificateCheck
                    $scanHistory.history | ForEach-Object {
                        if ($(convertToISO($_.creation_date) | Get-Date -format "dddd-d") -eq $getDate) {
                            #Write-Host "Going to export $_"
                            Write-Host "Scan History ID Found $($_.history_id)"
                            $currentConvertedTime = convertToISO($_.creation_date)
                            export -scanId $currentId -historyId $_.history_id -currentConvertedTime $currentConvertedTime -scanName $scanName
                            Write-Host "Finished export of $currentId, going to update status..."
                        } else {
                            #Write-Host "Nothing found" #$_
                            #convertToISO($_.creation_date)
                        }
                    }
                }
            } else {
                $global:listOfScans | ForEach-Object {
                    Write-Host "Going to export $($_.name)"
                    export -scanId $($_.id) -scanName $($_.name)
                    Write-Host "Finished export of $($_.name), going to update status..."
                }
            }
        }

        function Move-ScanToArchive{
            $body = [PSCustomObject]@{
                folder_id = $archiveFolderId
            } | ConvertTo-Json

            $ScanDetails = Invoke-RestMethod -Method Put -Uri "$Nessus_URL/scans/$($scanId)/folder" -Body $body -ContentType "application/json" -Headers $headers -SkipCertificateCheck
            Write-Host $ScanDetails -ForegroundColor Yellow
            Write-Host "Scan Moved to Archive - Export Complete." -ForegroundColor Green
        }

        function export ($scanId, $historyId, $currentConvertedTime, $scanName){
            Write-Host "Scan: $scanName exporting..."
            do {
                if($null -eq $currentConvertedTime){
                    $convertedTime = convertToISO($($global:currentNessusScanDataRaw.scans | Where-Object {$_.id -eq $scanId}).creation_date)
                }else{
                    $convertedTime = $currentConvertedTime
                }
                $exportFileName = Join-Path $Nessus_File_Download_Location $($($convertedTime | Get-Date -Format yyyy_MM_dd).ToString()+"-$($scanName)"+"-$scanId$($Export_Custom_Extended_File_Name_Attribute).nessus")
                $exportComplete = 0
                $currentScanIdStatus = $($global:currentNessusScanDataRaw.scans | Where-Object {$_.id -eq $scanId}).status
                #Check to see if scan is not running or is an empty scan, if true then lets export!
                if ($currentScanIdStatus -ne 'running' -and $currentScanIdStatus -ne 'empty' -or $historyId) {
                    $scanExportOptions = [PSCustomObject]@{
                        "format" = "nessus"
                    } | ConvertTo-Json
                    #Start the export process to Nessus has the file prepared for download
                    if($historyId){$historyIdFound = "?history_id=$historyId"}else {$historyId = $null}
                    $exportInfo = Invoke-RestMethod -Method Post "$Nessus_URL/scans/$($scanId)/export$($historyIdFound)" -Body $scanExportOptions -ContentType "application/json" -Headers $headers -SkipCertificateCheck
                    $exportStatus = ''
                    while ($exportStatus.status -ne 'ready') {
                        try {
                            $exportStatus = Invoke-RestMethod -Method Get "$Nessus_URL/scans/$($ScanId)/export/$($exportInfo.file)/status" -ContentType "application/json" -Headers $headers -SkipCertificateCheck
                            Write-Host "Export status: $($exportStatus.status)"
                        }
                        catch {
                            Write-Host "An error has occurred while trying to export the scan"
                            break
                        }
                        Start-Sleep -Seconds 1
                    }
                    #Time to download the Nessus scan!
                    Invoke-RestMethod -Method Get -Uri "$Nessus_URL/scans/$($scanId)/export/$($exportInfo.file)/download" -ContentType "application/json" -Headers $headers -OutFile $exportFileName -SkipCertificateCheck
                    $exportComplete = 1
                    Write-Host "Export succeeded!" -ForegroundColor Green
                    if ($null -ne $Nessus_Archive_Folder_Name) {
                        #Move scan to archive if folder is configured!
                        Write-Host "Archive scan folder configured so going to move the scan in the Nessus web UI to $Nessus_Archive_Folder_Name" -Foreground Yellow
                        Move-ScanToArchive
                    } else {
                        Write-Host "Archive folder not configured so not moving scan in the Nessus web UI." -Foreground Yellow
                    }

                }
                #If a scan is empty because it hasn't been started skip the export and move on.
                if ($currentScanIdStatus -eq 'empty') {
                    Write-Host "Scan has not been started, therefore skipping this scan."
                    $exportComplete = 2
                }
                if ($exportComplete -eq 0 ){
                    sleep5Minutes
                    updateStatus
                }
            } While ($exportComplete -eq 0)

        }

        $x = 3
        do {
            getScanIdsAndExport
            #Stop Nessus to get a fresh start
            if ($global:currentNessusScanData.Status -notcontains 'running') {
            } else {
                Write-Host 'Nessus has issues, investigate now!'
            }
            $x = 1
        } while ($x -gt 2)

        Write-Host "Finished Exporting!" -ForegroundColor White
    }

    function Invoke-Import_Nessus_To_Elasticsearch {
        Param (
            # Nessus XML file path
            [Parameter(Mandatory=$true)]
            $Nessus_XML_File,
            # Add Elasticsearch URL to automate Nessus import (default - https://127.0.0.1:9200)
            [Parameter(Mandatory=$true)]
            $Elasticsearch_URL,
            # Add Elasticsearch index name to automate Nessus import (default - logs-nessus.vulnerability)
            [Parameter(Mandatory=$true)]
            $Elasticsearch_Index_Name,
            # Elasticsearch API Key
            [Parameter(Mandatory=$true)]
            $Elasticsearch_API_Key
        )

        $ErrorActionPreference = 'Stop'
        $nessus = [xml]''
        $nessus.Load($Nessus_XML_File)

        #Elastic Instance (Hard code values here)
        #$Elasticsearch_IP = '127.0.0.1'
        #$Elasticsearch_Port = '9200'

        if ($Elasticsearch_URL -ne "https://127.0.0.1:9200") {
            Write-Host "Using the URL you provided for Elastic: $Elasticsearch_URL" -ForegroundColor Green
        } else {
            Write-Host "Running script with default localhost Elasticsearch URL ($Elasticsearch_URL)." -ForegroundColor Yellow
        }
        #Nessus User Authenitcation Variables for Elastic
        if ($Elasticsearch_API_Key) {
            Write-Host "Using the Api Key you provided." -ForegroundColor Green
        } else {
            Write-Host "Elasticsearch API Key Required! Go here if you don't know how to obtain one - https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html" -ForegroundColor "Red"
            break
        }
        $global:AuthenticationHeaders = @{Authorization = "ApiKey $Elasticsearch_API_Key"}

        #Create index name
        if ($Elasticsearch_Index_Name -ne "logs-nessus.vulnerability" ) {
            Write-Host "Using the Index you provided: $Elasticsearch_Index_Name" -ForegroundColor Green
        } else {
            $Elasticsearch_Index_Name = "logs-nessus.vulnerability"; Write-Host "No Index was entered, using the default value of $Elasticsearch_Index_Name" -ForegroundColor Yellow
        }
        
        function convertEpochSecondsToISO {
            Param($epochTime)
            $dateTime = [System.DateTimeOffset]::FromUnixTimeMilliseconds($epochTime).DateTime
            $newTime = Get-Date $dateTime -Format "o"
            return $newTime
        }

        #Now let the magic happen!
        Write-Host "
        Starting ingest of $Nessus_XML_File.

        The time it takes to parse and ingest will vary on the file size. 
        
        Note: Files larger than 1GB could take over 35 minutes.

        You can check if data is getting ingested by visiting Kibana and look under Index Management for this index: $Elasticsearch_Index_Name

        For debugging uncomment:
        #`$data.items | ConvertTo-Json -Depth 5
        "
        $fileProcessed = (Get-ChildItem $Nessus_XML_File).name
        $reportName = $nessus.NessusClientData_v2.Report.name
        foreach ($n in $nessus.NessusClientData_v2.Report.ReportHost) {
            foreach ($r in $n.ReportItem) {
                foreach ($nHPTN_Item in $n.HostProperties.tag) {
                #Get useful tag information from the report
                switch -Regex ($nHPTN_Item.name)
                    {
                    "host-ip" {$ip = $nHPTN_Item."#text"}
                    "host-fqdn" {$fqdn = $nHPTN_Item."#text"}
                    "host-rdns" {$rdns = $nHPTN_Item."#text"}
                    "operating-system-unsupported" {$osu = $nHPTN_Item."#text"}
                    "system-type" {$systype = $nHPTN_Item."#text"}
                    "^os$" {$os = $nHPTN_Item."#text"}
                    "operating-system$" {$opersys = $nHPTN_Item."#text"}
                    "operating-system-conf" {$operSysConfidence = $nHPTN_Item."#text"}
                    "operating-system-method" {$operSysMethod = $nHPTN_Item."#text"}
                    "^Credentialed_Scan" {$credscan = $nHPTN_Item."#text"}
                    "mac-address" {$macAddr = $nHPTN_Item."#text"}
                    "HOST_START_TIMESTAMP$" {$hostStart = $nHPTN_Item."#text"}
                    "HOST_END_TIMESTAMP$" {$hostEnd = $nHPTN_Item."#text"}
                    }
                }
                #Convert seconds to milliseconds
                $hostStart = $([int]$hostStart*1000)
                $hostEnd =  $([int]$hostEnd*1000)
                #Create duration and convert milliseconds to nano seconds
                $duration =  $(($hostEnd - $hostStart)*1000000)

                #Convert start and end dates to ISO
                $hostStart = convertEpochSecondsToISO $hostStart
                $hostEnd = convertEpochSecondsToISO $hostEnd

                $obj = [PSCustomObject]@{
                    "@timestamp" = $hostStart #Remove later for at ingest enrichment
                    "destination" = [PSCustomObject]@{
                        "port" = $r.port
                    }                
                    "event" = [PSCustomObject]@{
                        "category" = "host" #Remove later for at ingest enrichment
                        "kind" = "state" #Remove later for at ingest enrichment
                        "duration" = $duration
                        "start" = $hostStart
                        "end" = $hostEnd
                        "risk_score" = $r.severity
                        "dataset" = "vulnerability" #Remove later for at ingest enrichment
                        "provider" = "Nessus" #Remove later for at ingest enrichment
                        "message" = $n.name + ' - ' + $r.synopsis #Remove later for at ingest enrichment
                        "module" = "ImportTo-Elasticsearch-Nessus"
                        "severity" = $r.severity #Remove later for at ingest enrichment
                        "url" = (@(if($r.cve){($r.cve | ForEach-Object {"https://cve.mitre.org/cgi-bin/cvename.cgi?name=$_"})}else{$null})) #Remove later for at ingest enrichment
                    }
                    "host" = [PSCustomObject]@{
                        "ip" = $ip
                        "mac" = (@(if($macAddr){($macAddr.Split([Environment]::NewLine))}else{$null}))
                        "hostname" = if($fqdn -notmatch "sources" -and ($fqbn)){($fqdn).ToLower()}elseif($rdns){($rdns).ToLower()}else{$null} #Remove later for at ingest enrichment #Also, added a check for an extra "sources" sub field added to the fqbn field
                        "name" = if($fqdn -notmatch "sources" -and ($fqbn)){($fqdn).ToLower()}elseif($rdns){($rdns).ToLower()}else{$null} #Remove later for at ingest enrichment #Also, added a check for an extra "sources" sub field added to the fqbn field
                        "os" = [PSCustomObject]@{
                            "family" = $os
                            "full" = @(if($opersys){$opersys.Split("`n`r")}else{$null})
                            "name" = @(if($opersys){$opersys.Split("`n`r")}else{$null})
                            "platform" = $os
                        }
                    }
                    "log" = [PSCustomObject]@{
                        "origin" = [PSCustomObject]@{
                            "file" = [PSCustomObject]@{
                                "name" =  $fileProcessed
                            }
                        }
                    }
                    "nessus" = [PSCustomObject]@{
                        "cve" = (@(if($r.cve){($r.cve).ToLower()}else{$null}))
                        "in_the_news" = if($r.in_the_news){$r.in_the_news}else{$null}
                        "solution" = $r.solution
                        "synopsis" = $r.synopsis
                        "unsupported_os" = if($osu){$osu}else{$null}
                        "system_type" = $systype
                        "credentialed_scan" = $credscan
                        "exploit_available" = $r.exploit_available
                        "edb-id" = $r."edb-id"
                        "unsupported_by_vendor" = $r.unsupported_by_vendor
                        "os_confidence" = $operSysConfidence
                        "os_identification_method" = $operSysMethod
                        "rdns" = $rdns
                        "name_of_host" = $n.name.ToLower()
                        "cvss" = [PSCustomObject]@{
                            "vector" = if($r.cvss_vector){$r.cvss_vector}else{$null}
                            "base_score" = if($r.cvss_base_score){$r.cvss_base_score}else{$null}
                            "impact_score" = if($r.cvss_impactScore){$r.cvss_impactScore}else{$null}
                            "temporal_score" = if($r.cvss_temporal_score){$r.cvss_temporal_score}else{$null}
                        }
                        "cvss3" = [PSCustomObject]@{
                            "vector" = if($r.cvss3_vector){$r.cvss3_vector}else{$null}
                            "base_score" = if($r.cvss3_base_score){$r.cvss3_base_score}else{$null}
                            "impact_score" = if($r.cvssV3_impactScore){$r.cvssV3_impactScore}else{$null}
                            "temporal_score" = if($r.cvss3_temporal_score){$r.cvss3_temporal_score}else{$null}
                        }
                        "plugin" = [PSCustomObject]@{
                            "id" = $r.pluginID
                            "name" = $r.pluginName
                            "publication_date" = $r.plugin_publication_date
                            "type" = $r.plugin_type
                            "output" = $r.plugin_output
                            "filename" = $r.fname
                            "modification_date" = if($r.plugin_modification_date){$r.plugin_modification_date}else{$null}
                        }
                        "vpr_score" = if($r.vpr_score){$r.vpr_score}else{$null}
                        "exploit_code_maturity" = if($r.exploit_code_maturity){$r.exploit_code_maturity}else{$null}
                        "exploitability_ease" = if($r.exploitability_ease){$r.exploitability_ease}else{$null}
                        "age_of_vuln" = if($r.age_of_vuln){$r.age_of_vuln}else{$null}
                        "patch_publication_date" = if($r.patch_publication_date){$r.patch_publication_date}else{$null}
                        "stig_severity" = if($r.stig_severity){$r.stig_severity}else{$null}
                        "threat" = [PSCustomObject]@{
                            "intensity_last_28" = if($r.threat_intensity_last_28){$r.threat_intensity_last_28}else{$null}
                            "recency" = if($r.threat_recency){$r.threat_recency}else{$null}
                            "sources_last_28" = if($r.threat_sources_last_28){$r.threat_sources_last_28}else{$null}
                        }
                        "vuln_publication_date" = if($r.vuln_publication_date){$r.vuln_publication_date}else{$null}
                        "product_coverage" = if($r.product_coverage){$r.product_coverage}else{$null}
                    }
                    "network" = [PSCustomObject]@{
                        "transport" = $r.protocol
                        "application" = $r.svc_name
                    }
                    "vulnerability" = [PSCustomObject]@{
                        "id" = (@(if($r.cve){($r.cve)}else{$null}))
                        "category" = $r.pluginFamily
                        "description" = $r.description
                        "severity" = $r.risk_factor
                        "reference" = (@(if($r.see_also){($r.see_also.Split("`n"))}else{$null}))
                        "report_id" = $reportName
                        "module" = $r.pluginName
                        "classification" = (@(if($r.cve){("CVE")}else{$null}))
                        "score" = [PSCustomObject]@{
                            "base" = $r.cvss_base_score
                            "temporal" = $r.cvss_temporal_score
                        }
                    }

                } | ConvertTo-Json -Compress -Depth 5
                
                $hash += "{`"create`":{ } }`r`n$obj`r`n"
                #$Clean up variables
                $ip = ''
                $fqdn = ''
                $osu = ''
                $systype = ''
                $os = ''
                $opersys = ''
                $credscan = ''
                $macAddr = ''
                $hostStart = ''
                $hostEnd = ''
                $rdns = ''
                $operSysConfidence = ''
                $operSysMethod = ''

            }
            #Uncomment below to see the hash
            #$hash
            $ProgressPreference = 'SilentlyContinue'
            $data = Invoke-RestMethod -Uri "$Elasticsearch_URL/$Elasticsearch_Index_Name/_bulk" -Method POST -ContentType "application/x-ndjson; charset=utf-8" -body $hash -Headers $global:AuthenticationHeaders -SkipCertificateCheck

            #Error checking
            #$data.items | ConvertTo-Json -Depth 5

            $hash = ''
        }
    }

    function Invoke-Automate_Nessus_File_Imports {
        Param (
            # The location where you wish to save the extracted Nessus files from the scanner (default - Nessus_Exports)
            [Parameter(Mandatory=$true)]
            $Nessus_File_Download_Location,
            # Add Elasticsearch URL to automate Nessus import (default - https://127.0.0.1:9200)
            [Parameter(Mandatory=$true)]
            $Elasticsearch_URL,
            # Add Elasticsearch index name to automate Nessus import (default - logs-nessus.vulnerability)
            [Parameter(Mandatory=$true)]
            $Elasticsearch_Index_Name,
            # Elasticsearch Api Key
            [Parameter(Mandatory=$true)]
            $Elasticsearch_API_Key
        )

        $ProcessedHashesPath = "ProcessedHashes.txt"
        #Check to see if export scan directory exists, if not, create it!
        if ($false -eq $(Test-Path -Path $Nessus_File_Download_Location)) {
            Write-Host "Could not find $Nessus_File_Download_Location so creating that directory now."
            New-Item $Nessus_File_Download_Location -ItemType Directory
        }
        #Check to see if ProcessedHashses.txt file exists, if not, create it!
        if ($false -eq $(Test-Path -Path $processedHashesPath)) {
            Write-Host "Could not find $processedHashesPath so creating that file now."
            New-Item $processedHashesPath
        }
        
        #Check to see if parsedTime.txt file exists, if not, create it!
        if ($false -eq $(Test-Path -Path "parsedTime.txt")) {
            Write-Host "Could not find parsedTime.txt so creating that file now."
            New-Item "parsedTime.txt"
        }

        #Start ingesting 1 by 1!
        $allFiles = Get-ChildItem -Path $Nessus_File_Download_Location
        $allProcessedHashes = Get-Content $processedHashesPath
        $allFiles | ForEach-Object {
            #Check if already processed by name and hash
            if ($_.Name -like '*.nessus' -and ($allProcessedHashes -notcontains $($_ | Get-FileHash).Hash)) {
                $starting = Get-Date
                $Nessus_XML_File = Join-Path $Nessus_File_Download_Location -ChildPath $_.Name
                $markProcessed = "$($_.Name).processed"
                Write-Host "Going to process $_ now."
                Invoke-Import_Nessus_To_Elasticsearch -Nessus_XML_File $_ -Elasticsearch_URL $Elasticsearch_URL -Elasticsearch_Index $Elasticsearch_Index_Name -Elasticsearch_API_Key $Elasticsearch_API_Key
                $ending = Get-Date
                $duration = $ending - $starting
                $($Nessus_XML_File+'-PSNFscript-'+$duration | Out-File $(Resolve-Path parsedTime.txt).Path -Append)
                $($_ | Get-FileHash).Hash.toString() | Add-Content $processedHashesPath
                Write-Host "$Nessus_XML_File processed in $duration"
                Rename-Item -Path $_ -NewName $markProcessed
            } else {
                Write-Host "The file $($_.Name) doesn't end in .nessus or has already been processed in the $ProcessedHashesPath file. This file is used for tracking what files have been ingested to prevent duplicate ingest of data."
                Write-Host "If it's already been processed and you want to process it again, remove the hash from the $ProcessedHashesPath file or just remove it entirely for a clean slate."
            }
        }
        
        Write-Host "End of automating script!" -ForegroundColor Green
    }

    function Invoke-Purge_Processed_Hashes_List {
        Remove-Item .\ProcessedHashes.txt -Force
    }

    function Invoke-Revert_Nessus_To_Processed_Rename {
        Param (
            # The location where you wish to save the extracted Nessus files from the scanner (default - Nessus_Exports)
            [Parameter(Mandatory=$true)]
            $Nessus_File_Download_Location
        )
        # Get all files in the directory with the .nessus.processed extension
        $allFiles = Get-ChildItem -Path $Nessus_File_Download_Location -Filter *.processed
        
        # Rename each file
        foreach ($file in $allFiles) {
            $newName = $file.FullName -replace '\.processed$', ''
            Rename-Item -Path $file.FullName -NewName $newName -Force
        }
    }

    function Invoke-Purge_Oldest_Scan_From_History {
        Param ( 
        [Parameter(Mandatory=$true)]
        $Nessus_Scan_Name_To_Delete_Oldest_Scan
        )

        $headers =  @{'X-ApiKeys' = "accessKey=$Nessus_Access_Key; secretKey=$Nessus_Secret_Key"}
        
        # Don't parse the file downloads because we care about speed!
        $ProgressPreference = 'SilentlyContinue'
        getFolderIdFromName $Nessus_Source_Folder_Name, $Nessus_Archive_Folder_Name
        updateStatus
        $global:listOfScans | Where-Object -Property name -eq $Nessus_Scan_Name_To_Delete_Oldest_Scan
        $scanId = $($global:listOfScans | Where-Object -Property name -eq $Nessus_Scan_Name_To_Delete_Oldest_Scan).id
        if($null -eq $scanId){
            Write-Host "Invalid scan name entered ($Nessus_Scan_Name_To_Delete_Oldest_Scan) - exiting script" -ForegroundColor Yellow
            exit
        } else {
            Write-Host "Valid scan name found ($Nessus_Scan_Name_To_Delete_Oldest_Scan)" -ForegroundColor Green
        }
        $scanHistory = Invoke-RestMethod -Method Get -Uri "$Nessus_URL/scans/$($scanId)?limit=2500" -ContentType "application/json" -Headers $headers -SkipCertificateCheck
        $scanHistorySorted = $scanHistory.history | Select-Object -Property history_id, @{Name='creation_date'; Expression={convertToISO($_.creation_date)|Get-Date -Format 'MM/dd/yyyy HH:mm:ss'}}, status | Sort-Object -Property creation_date
        $oldestStartDate =  $scanHistorySorted[0].creation_date
        $oldestStatus = $scanHistorySorted[0].status
        $oldestHistoryId = $scanHistorySorted[0].history_id
        $scanHistorySorted 
        Write-Host "Found $($($scanHistory.history).count) total scans for $($scanHistory.info.name)"
        Write-Host "The oldest scan will be deleted. Details below:`nScan Started: $oldestStartDate`nScan Status: $oldestStatus`nScan History Id: $oldestHistoryId"
        try{
            # Delete scan
            Write-Host "Deleting scan! $Nessus_Scan_Name_To_Delete_Oldest_Scan (Id-$scanId,History Id-$oldestHistoryId)" -ForegroundColor Magenta
            $deleteScan = Invoke-RestMethod -Method Delete -Uri "$Nessus_URL/scans/$($scanId)/history/$oldestHistoryId" -ContentType "application/json" -Headers $headers -SkipCertificateCheck
            Write-Host "Scan successfully deleted!"
        } catch {
            Write-Host "Scan could not be deleted. $_"
        }

        Write-Host "End of oldest scan deletion script!" -ForegroundColor Green
    }

}

Process {

    while ($true -ne $finished) {
        # Show Menu if script was not provided the choice on execution using the Option_Selected variable
        if ($null -eq $Option_Selected) {
            Show-Menu
            $Option_Selected = Read-Host "Enter your choice"
        }
    
        switch ($Option_Selected) {
            '0' {
                Write-Host "You selected Option $option0"
                
                #Check for Elasticserach URL, Kibana Url, and elastic credentials
                $Elasticsearch_URL = Read-Host "Elasticsearch URL"
                $Kibana_URL = Read-Host "Kibana URL"
                $Elasticsearch_Credentials = Get-Credential elastic
                $Elasticsearch_Credentials_Base64 = [convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($($Elasticsearch_Credentials.UserName+":"+$($Elasticsearch_Credentials.Password | ConvertFrom-SecureString -AsPlainText)).ToString()))
                $Kibana_Credentials = "Basic $Elasticsearch_Credentials_Base64"

                #Import Ingest Pipelines
                Write-Host "Setting up customized Nessus Elasticsearch ingest pipeline." -ForegroundColor Blue
                $pipelineName = "logs-nessus.vulnerability"
                $ingestPipelineJSON = Get-Content $(Join-Path .\pipelines -ChildPath "$pipelineName.json")
                $ingestPipelineURL = $Elasticsearch_URL+"/_ingest/pipeline/"+$pipelineName
                try { 
                    $createPipeline = Invoke-RestMethod -Method PUT -Uri $ingestPipelineURL -Body $ingestPipelineJSON -ContentType "application/json" -Credential $Elasticsearch_Credentials -AllowUnencryptedAuthentication -SkipCertificateCheck
                    if ($createPipeline.acknowledged -eq $true) {
                        Write-Host "The pipeline $pipelineName was successfully created!" -ForegroundColor Green
                        Write-Host "Check it out here: $Kibana_URL/app/management/ingest/ingest_pipelines/?pipeline=$pipelineName" -ForegroundColor Blue
                    } else {
                        Write-Host "Pipeline failed to get created."
                    }
                } catch {
                    Write-Host "Couldn't add ingest pipeline, likely because it already exists. Check kibana to see if the ingest pipeline $pipelineName exists." -ForegroundColor Yellow
                }

                #Import Index Template
                Write-Host "Setting up customized Elasticsearch index template." -ForegroundColor Blue
                $indexTemplateName = "logs-nessus.vulnerability"
                $indexTemplateNameJSON = Get-Content $(Join-Path .\templates -ChildPath "$indexTemplateName.json")
                $indexTemplateURL = $Elasticsearch_URL+"/_index_template/"+$indexTemplateName
                try { 
                    $createIndexTemplate = Invoke-RestMethod -Method PUT -Uri $indexTemplateURL -Body $indexTemplateNameJSON -ContentType "application/json" -Credential $Elasticsearch_Credentials -AllowUnencryptedAuthentication -SkipCertificateCheck
                    if ($createIndexTemplate.acknowledged -eq $true) {
                        Write-Host "The index template $indexTemplateName was successfully created!" -ForegroundColor Green
                        Write-Host "Check it out here: $Kibana_URL/app/management/data/index_management/templates/$indexTemplateName" -ForegroundColor Blue
                    } else {
                        Write-Host "Index template failed to get created."
                    }
                } catch {
                    Write-Host "Couldn't add index template, likely because it already exists. Check kibana to see if the ingest pipeline $indexTemplateName exists." -ForegroundColor Yellow
                }

                #Import Saved Objects
                $dashboardsPath = $(Resolve-Path .\dashboards).path
                $importSavedObjectsURL = $Kibana_URL+"/api/saved_objects/_import?overwrite=true"
                $kibanaHeader = @{"kbn-xsrf" = "true"; "Authorization" = "$Kibana_Credentials"}
                $allDashboardFiles = Get-ChildItem $dashboardsPath
                $allDashboardFiles | ForEach-Object {
                    $fileBytes = [System.IO.File]::ReadAllBytes($_.FullName);
                    $fileEnc = [System.Text.Encoding]::GetEncoding('UTF-8').GetString($fileBytes);
                    $boundary = [System.Guid]::NewGuid().ToString(); 
                    $LF = "`r`n";
    
                    $bodyLines = ( 
                        "--$boundary",
                        "Content-Disposition: form-data; name=`"file`"; filename=`"$($_.name)`"",
                        "Content-Type: application/octet-stream$LF",
                        $fileEnc,
                        "--$boundary--$LF" 
                    ) -join $LF
    
                    $result = Invoke-RestMethod -Method POST -Uri $importSavedObjectsURL -Headers $kibanaHeader -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines -AllowUnencryptedAuthentication -SkipCertificateCheck
                    if($result.errors -or $null -eq $result){
                        Write-Host "There was an error trying to import $filename"
                        $result.errors
                    }
                    $fileBytes = $null
                    $fileEnc = $null
                    $boundary = $null
                    $result = $null
                }

                #Create Nessus API Key
                Write-Host "Setting up customized Nessus Elasticsearch API Key for writing to logs-nessus.vulnerability data stream." -ForegroundColor Blue
                $logsNessusAPIKey = "logs-nessus.vulnerability-api-key"
                $logsNessusAPIKeyJSON = Get-Content $(Join-Path .\templates -ChildPath "$logsNessusAPIKey.json")
                $createAPIKeyURL = $Elasticsearch_URL+"/_security/api_key"
                try { 
                    $createAPIKey = Invoke-RestMethod -Method PUT -Uri $createAPIKeyURL -Body $logsNessusAPIKeyJSON -ContentType "application/json" -Credential $Elasticsearch_Credentials -AllowUnencryptedAuthentication -SkipCertificateCheck
                    if ($createAPIKey.encoded) {
                        Write-Host "The Nessus API key was successfully created!" -ForegroundColor Green
                        Write-Host "Here is your encoded API Key that can be used to ingest your Nessus scan data into the $($createApiKey.name) data stream.`nStore in a safe place: $($createApiKey.encoded)"
                    } else {
                        Write-Host "API Key failed to get created." -ForegroundColor Yellow
                    }
                } catch {
                    Write-Host "API Key failed to get created. $_" -ForegroundColor Yellow
                }

                $finished = $true
            }
            '1' {
                Write-Host "You selected Option $option1"
                
                #Check for Nessus Access and Nessus Secret Key and Prompt if not provided
                if($null -eq $Nessus_Access_Key){
                    $Nessus_Access_Key = Read-Host "Nessus Access Key"
                }
                if($null -eq $Nessus_Secret_Key){
                    $Nessus_Secret_Key = Read-Host "Nessus Secret Key"
                }

                Invoke-Exract_From_Nessus -Nessus_URL $Nessus_URL -Nessus_File_Download_Location $Nessus_File_Download_Location -Nessus_Access_Key $Nessus_Access_Key -Nessus_Secret_Key $Nessus_Secret_Key -Nessus_Source_Folder_Name $Nessus_Source_Folder_Name -Nessus_Archive_Folder_Name $Nessus_Archive_Folder_Name -Export_Scans_From_Today $Export_Scans_From_Today -Export_Day $Export_Day -Export_Custom_Extended_File_Name_Attribute $Export_Custom_Extended_File_Name_Attribute
                $finished = $true
            }
            '2' {
                Write-Host "You selected Option $option2"

                #Check for Nessus XML File you wish to process
                if($null -eq $Nessus_XML_File){
                    $Nessus_XML_File = Read-Host "Nessus XML File (.nessus)"
                }

                #Check for Elasticsearch URL and API Keys and prompt if not provided
                if($null -eq $Elasticsearch_URL){
                    $Elasticsearch_URL = Read-Host "Elasticsearch URL (https://127.0.0.1:9200)"
                }
                if($null -eq $Elasticsearch_Api_Key){
                    $Elasticsearch_Api_Key = Read-Host "Elasticsearch API Key"
                }

                Invoke-Import_Nessus_To_Elasticsearch -Nessus_XML_File $Nessus_XML_File -Elasticsearch_URL $Elasticsearch_URL -Elasticsearch_Index_Name $Elasticsearch_Index_Name -Elasticsearch_API_Key $Elasticsearch_Api_Key
                $finished = $true
            }
            '3' {
                Write-Host "You selected Option $option3"

                #Check for Elasticsearch URL and API Keys and prompt if not provided
                if($null -eq $Elasticsearch_URL){
                    $Elasticsearch_URL = Read-Host "Elasticsearch URL (https://127.0.0.1:9200)"
                }
                if($null -eq $Elasticsearch_Api_Key){
                    $Elasticsearch_Api_Key = Read-Host "Elasticsearch API Key"
                }
                if($null -eq $Nessus_File_Download_Location){
                    $Nessus_File_Download_Location = Read-Host "Nessus File Download Location (default - Nessus Exports)"
                }

                Invoke-Automate_Nessus_File_Imports -Nessus_File_Download_Location $Nessus_File_Download_Location -Elasticsearch_URL $Elasticsearch_URL -Elasticsearch_Index_Name $Elasticsearch_Index_Name -Elasticsearch_API_Key $Elasticsearch_Api_Key
                
                $finished = $true
            }
            '4' {
                Write-Host "You selected Option $option4." -ForegroundColor Yellow
                
                #Check for Nessus Access and Nessus Secret Key and Prompt if not provided
                if($null -eq $Nessus_Access_Key){
                    $Nessus_Access_Key = Read-Host "Nessus Access Key"
                }
                if($null -eq $Nessus_Secret_Key){
                    $Nessus_Secret_Key = Read-Host "Nessus Secret Key"
                }

                #Check for Elasticsearch URL and API Keys and prompt if not provided
                if($null -eq $Elasticsearch_URL){
                    $Elasticsearch_URL = Read-Host "Elasticsearch URL (https://127.0.0.1:9200)"
                }
                if($null -eq $Elasticsearch_Api_Key){
                    $Elasticsearch_Api_Key = Read-Host "Elasticsearch API Key"
                }

                Invoke-Exract_From_Nessus -Nessus_URL $Nessus_URL -Nessus_File_Download_Location $Nessus_File_Download_Location -Nessus_Access_Key $Nessus_Access_Key -Nessus_Secret_Key $Nessus_Secret_Key -Nessus_Source_Folder_Name $Nessus_Source_Folder_Name -Nessus_Archive_Folder_Name $Nessus_Archive_Folder_Name -Export_Scans_From_Today $Export_Scans_From_Today -Export_Day $Export_Day -Export_Custom_Extended_File_Name_Attribute $Export_Custom_Extended_File_Name_Attribute

                Invoke-Automate_Nessus_File_Imports -Nessus_File_Download_Location $Nessus_File_Download_Location -Elasticsearch_URL $Elasticsearch_URL -Elasticsearch_Index_Name $Elasticsearch_Index_Name -Elasticsearch_API_Key $Elasticsearch_Api_Key

                $finished = $true
                break
            }
            '5' {
                Write-Host "You selected Option $option5." -ForegroundColor Yellow
                Invoke-Purge_Processed_Hashes_List
                Invoke-Revert_Nessus_To_Processed_Rename $Nessus_File_Download_Location
                $finished = $true
                break
            }
            '10' {
                Write-Host "You selected Option $option10." -ForegroundColor Yellow
                if($null -eq $Nessus_Scan_Name_To_Delete_Oldest_Scan){
                    $Nessus_Scan_Name_To_Delete_Oldest_Scan = Read-Host "Nessus Scan Name to Delete Oldest Scan"
                }
                Invoke-Purge_Oldest_Scan_From_History $Nessus_Scan_Name_To_Delete_Oldest_Scan
                $finished = $true
                break
            }
            'Q' {
                Write-Host "You selected quit, exiting." -ForegroundColor Yellow
                $finished = $true
                break
            }
            default {
                Write-Host "Invalid choice. Please select a valid option."
            }
        }
    }

}

End {
    Write-Host "This is the end. Thanks for using this script!" -ForegroundColor Blue
    $finished = $null
}
