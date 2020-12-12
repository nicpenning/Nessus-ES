<#
.Synopsis
   Automatically check for any unprocessed .nessus files and call the ImportTo-Elasticsearch.ps1 script to ingest into Elastic.
   Pairs well with the ImportTo-Elasticsearch-Nessus.ps1 (mostly because it's pretty useless without it!).
.DESCRIPTION
   This script is useful for automating the ingest of Nessus scan files. The script will be able to allow for some customizations
   such as the Elasticsearch host and the location of the Nessus files.
   
   Requires:
   API Key for Elastic to authenticate
   ImportTo-Elasticsearch-Nessus.ps1
   Store this file in the same directory as the ImportTo-Elasticsearch-Nessus.ps1

.EXAMPLE
   .\Automate-NessusImport.ps1 -DownloadedNessusFileLocation "C:\Nessus" -ElasticsearchURL "http://127.0.0.1:9200" -IndexName "nessus" -ElasticsearchApiKey "redacted" 
#>

[CmdletBinding()]
[Alias()]
Param
(
    # The location of all downloaded .nessus files
    [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=0)]
    $DownloadedNessusFileLocation,
    # The Elasticsearch instance for ingesting .nessus files
    [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=1)]
    $ElasticsearchURL,
    # The name of the Elasticsearch index you wish to store the .nessus data
    [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=2)]
    $IndexName,
    # Elasticsearch Api Key
    [Parameter(Mandatory=$true,
        ValueFromPipelineByPropertyName=$true,
        Position=3)]
    $ElasticsearchAPIKey
)

Begin{
    $ProcessedHashesPath = "ProcessedHashes.txt"
}

Process{
    #Start ingesting 1 by 1!
    $allFiles = Get-ChildItem -Path $DownloadedNessusFileLocation
    $allProcessedHashes = Get-Content $processedHashesPath
    $allFiles | ForEach-Object{
        #Check if already processed by name and hash
        if($_.Name -like '*.nessus' -and ($allProcessedHashes -notcontains $($_ | Get-FileHash).Hash)){
            $starting = Get-Date
            $fileToProcess = $DownloadedNessusFileLocation+$_.Name
            $markProcessed = $DownloadedNessusFileLocation+$_.Name+".processed"
            Write-Host "Going to process $_ now."
            .\ImportTo-Elasticsearch-Nessus.ps1 -InputXML $fileToProcess -ElasticsearchURL $ElasticsearchURL -Index $IndexName -ElasticsearchApiKey $ElasticsearchAPIKey
            $ending = Get-Date
            $duration = $ending - $starting
            $($fileToProcess+'-PSNFscript-'+$duration | Out-File ".\parsedTime.txt" -Append)
            $($_ | Get-FileHash).Hash.toString() | Add-Content $processedHashesPath
            Write-Host "$fileToProcess processed in $duration"
            Rename-Item -Path $fileToProcess -NewName $markProcessed
        }
    }
}

End {
    Write-Host "End of exporting for all scans!" -ForegroundColor Green
}
