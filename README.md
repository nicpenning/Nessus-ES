# Nessus-ES
Ingest .nessus files from Tenable's Nessus scanner directly into ElasticSearch with most of the ECS mappings possible.

With some careful setup of your ElasticSearch cluster and a little PowerShell you can turn your .nessus files into this:
![](https://github.com/nicpenning/Nessus-ES/blob/master/Screen%20Shot%202020-04-22%20at%209.19.46%20PM.png?raw=true)

If you are looking for a more robust solution that handles many other vulnerability scanners try this project: https://github.com/HASecuritySolutions/VulnWhisperer

This project is a simplified way of taking .nessus files and ingesting them into Elastic using PowerShell on Windows, Mac, or Linux*

*Never tested

## Future
- [ ] Add Index Template (How To/Automate)
- [X] Add Index Pattern, Searches, Visualizations, and Dashboards
- [ ] Add Detection Rules
- [X] Have coverage of ECS across as many fields possible.
- [ ] Add Automated Nessus File Download Script
- [ ] Add Documentation (Setup, gotchas, and other good things to know.)


Here are some other details from the dashboard not pictured above that could also be useful:
![](https://github.com/nicpenning/Nessus-ES/blob/master/Nessus_Details_Dashboard.png?raw=true)
