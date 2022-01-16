<#
.Synopsis
   Parse Nessus XML report and import into Elasticsearch using the _bulk API.
.DESCRIPTION
   Parse Nessus XML report and convert to expected json format (x-ndjson)
   for Elasticsearch _bulk API.

   Original script credit found here --> https://github.com/iwikmai/Nessus-ES/blob/master/ImportTo-ElasticSearchBulk.ps1

   How to create and use an API key for Elastic can be found here: https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html

   Tested for Elastic Stack 7.6.1 - Should work on 7.0+, not tested on older clusters.

   Use -DomainName if you have Winlogbeat agents older than 7.6.0 and you want to use the SIEM App Hosts section. Ignore this setting if you are running 7.6.0 and newer Winlogbeat.
.EXAMPLE
   .\ImportTo-Elasticsearch-Nessus.ps1 -InputXML "C:\folder\file.nessus" -ElasticsearchURL "https://localhost:9200" -Index "nessus" -ElasticsearchAPIKey "redacted" -DomainName "organization.local"
#>

[CmdletBinding()]
[Alias()]
Param
(
    # XML file input
    [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=0)]
    $InputXML,
    # Elasticsearch endpoint
    [Parameter(Mandatory=$false,
                ValueFromPipelineByPropertyName=$true,
                Position=1)]
    $ElasticsearchURL,
    # Elasticsearch index mapping
    [Parameter(Mandatory=$false,
                ValueFromPipelineByPropertyName=$true,
                Position=2)]
    $Index,
    # Elasticsearch API Key
    [Parameter(Mandatory=$true,
                ValueFromPipelineByPropertyName=$true,
                Position=3)]
    $ElasticsearchAPIKey
)

Begin{
    if($PSVersionTable.PSVersion.Major -lt 7){
    #Trust certs
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
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy}else{
    
    }


    $ErrorActionPreference = 'Stop'
    $nessus = [xml]''
    $nessus.Load($InputXML)
}
Process{
    #Elastic Instance (Hard code values here)
    $ElasticsearchIP = '127.0.0.1'
    $ElasticsearchPort = '9200'
    if($ElasticsearchURL){Write-Host "Using the URL you provided for Elastic: $ElasticsearchURL" -ForegroundColor Green}else{$ElasticsearchURL = "https://"+$ElasticsearchIP+":"+$ElasticsearchPORT; Write-Host "Running script with manual configuration, will use static variables ($ElasticsearchURL)." -ForegroundColor Yellow}
    #Nessus User Authenitcation Variables for Elastic
    if($ElasticsearchAPIKey){Write-Host "Using the Api Key you provided." -ForegroundColor Green}else{Write-Host "Elasticsearch API Key Required! Go here if you don't know how to obtain one - https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html" -ForegroundColor "Red"; break;}
    $global:AuthenticationHeaders = @{Authorization = "ApiKey $ElasticsearchAPIKey"}

    #Create index name
    if($Index){Write-Host "Using the Index you provided: $Index" -ForegroundColor Green}else{$Index = "nessus-2021"; Write-Host "No Index was entered, using the default value of $Index" -ForegroundColor Yellow}
    
    #Now let the magic happen!
    Write-Host "
    Starting ingest of $InputXML.

    The time it takes to parse and ingest will vary on the file size. 
     
    Note: Files larger than 1GB could take over 35 minutes.

    You can check if data is getting ingested by visiting Kibana and look under Index Management for this index: $Index

    For debugging uncomment line 202.
    "
    $fileProcessed = (Get-ChildItem $InputXML).name
    $reportName = $nessus.NessusClientData_v2.Report.name
    foreach ($n in $nessus.NessusClientData_v2.Report.ReportHost){
        foreach($r in $n.ReportItem){
            foreach ($nHPTN_Item in $n.HostProperties.tag){
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
            $hostStart = [int]$hostStart*1000
            $hostEnd = [int]$hostEnd*1000
            #Convert milliseconds to nano seconds
            $duration = $(($hostEnd - $hostStart)*1000000)

            $obj=[PSCustomObject]@{
                "@timestamp" = $hostStart #Remove later for at ingest enrichment
                "destination" = [PSCustomObject]@{
                    "port" = $r.port
                }
                "ecs" = [PSCustomObject]@{
                    "version" = "1.5"
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
                        "vector" = $r.cvss_vector
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
                    "reference" = (@(if($r.see_also){($r.see_also.Split([Environment]::NewLine))}else{$null}))
                    "report_id" = $reportName
                    "module" = $r.pluginName #Remove later for at ingest enrichment
                    "classification" = (@(if($r.cve){("CVE")}else{$null})) #Remove later for at ingest enrichment
                    "score" = [PSCustomObject]@{
                        "base" = $r.cvss_base_score
                        "temporal" = $r.cvss_temporal_score
                    }
                }

            } | ConvertTo-Json -Compress -Depth 5
            
            $hash += "{`"index`":{`"_index`":`"$Index`"}}`r`n$obj`r`n"
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
            $cves = ''
            $rdns = ''
            $operSysConfidence = ''
            $operSysMethod = ''

        }
        #Uncomment below to see the hash
        #$hash
        $ProgressPreference = 'SilentlyContinue'
        try {
            $data = Invoke-RestMethod -Uri "$ElasticsearchURL/_bulk" -Method POST -ContentType "application/x-ndjson" -body $hash -Headers $global:AuthenticationHeaders
        }catch {
            $data = Invoke-RestMethod -Uri "$ElasticsearchURL/_bulk" -Method POST -ContentType "application/x-ndjson" -body $hash -Headers $global:AuthenticationHeaders -SkipCertificateCheck
        }
        
        #Error checking
        #$data.items | ConvertTo-Json -Depth 5

        $hash = ''
    }
}
End{
    Write-Host "End of exporting!" -ForegroundColor Green
}
