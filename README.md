# Nessus-ES
Ingest .nessus files from Tenable's Nessus scanner directly into ElasticSearch with most of the ECS mappings possible.

With some careful setup of your ElasticSearch cluster and a little PowerShell you can turn your .nessus files into this:
![](https://github.com/nicpenning/Nessus-ES/blob/master/Nessus_Dashboard.png)

If you are looking for a more robust solution that handles many other vulnerability scanners try this project: https://github.com/HASecuritySolutions/VulnWhisperer

The Nessus-ES project is a simplified way of taking .nessus files and ingesting them into Elastic using PowerShell on Windows, Mac, or Linux*

*Never tested

Requirements
* Functioning ElasticSearch Cluster (7.0+, 7.6.2 Tested)
* PowerShell
* .nessus File(s) Exported

## Now
- [X] Add Index Template (How To)
- [X] Add Index Pattern, Searches, Visualizations, and Dashboards
- [X] Have coverage of ECS across as many fields possible.
- [X] Add Documentation ([Wiki](https://github.com/nicpenning/Nessus-ES/wiki))

## Future
- [ ] Add Detection Rules
- [ ] Add Automated Nessus File Download Script
- [ ] Add Setup Script (Template, Objects, API, etc..)


Here are some other details from the dashboard not pictured above that could also be useful:
![](https://github.com/nicpenning/Nessus-ES/blob/master/Nessus_Details_Dashboard.png?raw=true)
