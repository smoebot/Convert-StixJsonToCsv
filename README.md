# Convert-StixJsonToCsv

Powershell.  Convert STIX (JSON format) IOCs to CSV format 

Useful for immediately extracting all IOCS from a STIX file, for manual input to systems that don't support STIX JSON

Provides Ipv4, URL, FQDN, MD5, SHA, and SHA256 columns

**Parameters**

_Inputfile_

[Mandatory]

The name of the STIX file in JSON format that you want to read in

_Outputfile_

[Mandatory]

The name of the file that you want the data to be written out to

**Examples**

```powershell
Convert-StixJsonToCsv -Inputfile kruger.json -Outputfile smoothing.csv
```
