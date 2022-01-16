# Nessus-ES
Ingest .nessus files from Tenable's Nessus scanner directly into ElasticSearch with most of the ECS mappings.

With some careful setup of your ElasticSearch cluster and a little PowerShell you can turn your .nessus files into this:
![](https://github.com/nicpenning/Nessus-ES/blob/master/Nessus_Dashboard.png)

If you are looking for a more robust solution that handles many other vulnerability scanners try this project: https://github.com/HASecuritySolutions/VulnWhisperer

The Nessus-ES project is a simplified way of taking .nessus files and ingesting them into Elastic using PowerShell on Windows, Mac, or Linux*

*Never tested

Requirements
* Functioning ElasticSearch Cluster (7.0+, 7.16.2 Tested)
* PowerShell
* .nessus File(s) Exported

## Now
- [X] Add Index Template (How To)
- [X] Add Index Pattern, Searches, Visualizations, and Dashboards
- [X] Have coverage of ECS across as many fields possible.
- [X] Add Documentation ([Wiki](https://github.com/nicpenning/Nessus-ES/wiki))
- [X] Add Automated Nessus File Download Script

## Future
- [ ] Add Detection Rules
- [ ] Add Setup Script (Template, Objects, API, etc..)
- [ ] Upgrade to ECS 1.12
- [ ] Revamp Dashboards to use Lens Visuals
- [ ] Create a release for easier deployment

## Added Automated Download and Ingest capability - Check the [Wiki](https://github.com/nicpenning/Nessus-ES/wiki)!
ExtractFrom-Nessus.ps1 -> Automate-NessusImport.ps1 -> ImportTo-Elasticsearch-Nessus.ps1


Here are some other details from the dashboard not pictured above that could also be useful:
![](https://github.com/nicpenning/Nessus-ES/blob/master/Nessus_Details_Dashboard.png?raw=true)
## New VPR Search added to Dashboard!
![](https://github.com/nicpenning/Nessus-ES/blob/master/Nessus_Details_VPR_Search_Dashboard.png?raw=true)
