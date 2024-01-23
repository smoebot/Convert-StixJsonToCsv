function Convert-StixJsonToCsv{
<#
    .SYNOPSIS
        Convert STIX (JSON format) IOCs to CSV format
    .DESCRIPTION
        Convert STIX (JSON Format) to CSV format.  
        Useful for immediately extracting all IOCS from a STIX file, for manual input to systems that don't support STIX JSON
        Provides Ipv4, URL, FQDN, MD5, SHA, and SHA256 columns
    .PARAMETER Inputfile
        [Mandatory]
        The name of the STIX file in JSON format that you want to read in
    .PARAMETER Outputfile
        [Mandatory]
        The name of the file that you want the data to be written out to
    .NOTES
        Author: Joel Ashman
        v0.1 - (2024-01-23) Initial version
    .EXAMPLE
        Convert-StixJsonToCsv -Inputfile kruger.json -Outputfile smoothing.csv
#>
    #requires -version 5    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InputFile,
        [Parameter(Mandatory=$true)]
        [string]$OutputFile
    )

    # Get the file, convert JSON into powershell object, and drill down into the object for the actual data
    $Json = get-content $InputFile
    $Data = ($Json | ConvertFrom-Json).objects

    # Build an array to store results in later
    $IndicatorArray = @()
    
    # Iterate through each object, ignore the non indicator objects, and parse out the relevant IOCs
    # Used Rons favourite (regex) to grab them, as it was easiest to use a capturing group for most, and pull them that way
    foreach ($Item in $Data){
        if ($Item.type -match "indicator"){
            $IndicatorObject = [PSCustomObject]@{
                'type' = $Item.type
                'subtype' = $Item.name.replace(" Indicator","")
                'disposition' = $Item.indicator_types.replace("{","").replace("}","")
                'ipv4' = [regex]::Match(($Item.pattern), "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
                'md5' = $Md5 = [regex]::Match(($Item.pattern), "^.*?\.MD5\s\=\s\'([a-fA-F0-9]{32})\'").Groups[1].value
                'sha' = [regex]::Match(($Item.pattern), "^.*?\.\'SHA\-1\'\s\=\s\'([a-fA-F0-9]{40})\'").Groups[1].value
                'sha256' = [regex]::Match(($Item.pattern), "^.*?\.\'SHA\-256\'\s\=\s\'([a-fA-F0-9]{64})\'").Groups[1].value
                'filename' = [regex]::Match(($Item.pattern), "^\[\(file\:name\s\=\s\'(.*?)'").Groups[1].value
                'filesize' = [regex]::Match(($Item.pattern), "^.*?file\:size\s\=\s(.*?)\s").Groups[1].value
                'url' = [regex]::Match(($Item.pattern), "^\[url\:value\s\=\s'(.*?)'.*?$").Groups[1].value
                'fqdn' = [regex]::Match(($Item.pattern), "^\[domain\-name\:value\s\=\s'(.*?)'.*?$").Groups[1].value
            }
        }
        # Add the built object to the Array
        $IndicatorArray += $IndicatorObject
    }
    # Sort the object and keep onluy unique values.  All properties have to be examined, otherwise -Unique disposes of most of the data
    $IndicatorArray | Sort-Object -Property type, subtype, disposition, ipv4, md5, sha, sha256, filename, filesize, url, fqdn -Unique | Export-Csv -Path $OutputFile -NoClobber -NoTypeInformation
}
