# Nessus-ES

An update is lurking...
![👀](https://github.com/nicpenning/Nessus-ES/assets/5582679/1a23deda-9a00-4ec4-9d99-013b7572aa91)


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

The Nessus-ES project is a simplified way of taking .nessus files and ingesting them into Elastic using PowerShell on Windows, Mac, or Linux.

Requirements
* Functioning Elastic Stack (7.0+, 8.12.1 Latest Tested)
* PowerShell 7.0+ (7.4.1 Latest Tested)
* .nessus File(s) Exported (Script included to export these files!)

Script includes a Menu to help you through how you would like to use this tool:
![image](https://github.com/nicpenning/Nessus-ES/assets/5582679/989727d5-65ee-49fd-9dd9-8e74724fd75e)

## Now
- [X] Index Template (How To)
- [X] Index Pattern, Searches, Visualizations, and Dashboards
- [X] ECS coverage across as many fields as possible
- [X] Documentation ([Wiki](https://github.com/nicpenning/Nessus-ES/wiki/Overview))
- [X] Automated Nessus File Download Script
- [X] Automated Elasticsearch Ingest
- [X] Setup Script (Template, Objects, API, etc..)

## Future
- [ ] Add Detection Rules
- [ ] Compare Scans (New Data Stream)
- [ ] Automate/Implement Latest CISA KEVs ([Feature Request](https://github.com/nicpenning/Nessus-ES/issues/13))

## Automated or Manual Download and Ingest capability - Check the [Wiki](https://github.com/nicpenning/Nessus-ES/wiki/Overview)!
Invoke-NessusTo-Elastic.ps1

## Full dashboard preview
https://github.com/nicpenning/Nessus-ES/assets/5582679/448505f5-7991-4554-b199-412dd5351329

