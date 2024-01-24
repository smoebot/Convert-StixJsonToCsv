# Convert-StixToCsv

Convert STIX to CSV format.

Supports JSON and XML files 

Useful for immediately extracting all IOCS from a STIX file, for manual input to systems that don't support STIX JSON or XML

Provides Ipv4, URL, FQDN, MD5, SHA, and SHA256 columns

Useful for immediately extracting all IOCS from a STIX file, for manual input to systems that don't support STIX JSON

Provides Ipv4, URL, FQDN, MD5, SHA, and SHA256 columns

**Parameters**

_Inputfile_

[Mandatory]

The name of the STIX file in JSON format that you want to read in

_Outputfile_

The name of the file that you want the data to be written out to

_View_
        
The type of IOC that you want displayed to the screen

Can be any of the following values: ip, fqdn, url, md5, sha, or sha256

**Examples**

```powershell
Convert-StixToCsv -Inputfile kruger.json -Outputfile smoothing.csv
```

```powershell
Convert-StixToCsv -Inputfile penske.xml -Outputfile material.csv -view fqdn
```
