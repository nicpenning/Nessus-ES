# Nessus-ES

Ingest .nessus files from Tenable's Nessus scanner directly into ElasticSearch with most of the ECS mappings.

```mermaid
  sequenceDiagram
    PowerShell->>Nessus: Downloads .Nessus File(s) via Nessus API
    Nessus->>PowerShell: .nessus File(s) Saved Locally
    PowerShell->>Kibana: Dashboards, Index Templates and other Setup items
    PowerShell->>Elasticsearch: Ingest Parsed XML Data via Elasticsearch API
```

With some careful setup of your Elastic stack and a little PowerShell you can turn your .nessus files into this:
![image](https://github.com/nicpenning/Nessus-ES/assets/5582679/746d143d-ff1a-4077-82c2-03e229f59bbf)

If you are looking for a more robust solution that handles many other vulnerability scanners try this project: https://github.com/HASecuritySolutions/VulnWhisperer

The Nessus-ES project is a simplified way of taking .nessus files and ingesting them into Elastic using PowerShell on Windows, Mac, or Linux.

Requirements
* Functioning Elastic Stack (7.0+, 8.11.0 Tested)
* PowerShell 7.0+ (7.3.8 Tested)
* .nessus File(s) Exported (Script included to export these files!)

Script now includes a Menu to help you through the process to use this tool:
![image](https://github.com/nicpenning/Nessus-ES/assets/5582679/db61fbba-352d-4d02-bb98-7c260a69a302)

## Now
- [X] Index Template (How To)
- [X] Index Pattern, Searches, Visualizations, and Dashboards
- [X] ECS coverage across as many fields as possible
- [X] Documentation ([Wiki](https://github.com/nicpenning/Nessus-ES/wiki/Overview))
- [X] Automated Nessus File Download Script
- [X] Automated Ingest
- [X] Create a release
- [X] Add Setup Script (Template, Objects, API, etc..)

## Future
- [ ] Add Detection Rules

## Automated or Manual Download and Ingest capability - Check the [Wiki](https://github.com/nicpenning/Nessus-ES/wiki/Overview)!
Invoke-NessusTo-Elastic.ps1

## Full dashboard preview
https://github.com/nicpenning/Nessus-ES/assets/5582679/448505f5-7991-4554-b199-412dd5351329

