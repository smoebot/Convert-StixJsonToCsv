function Convert-StixToCsv{
<#
    .SYNOPSIS
        Convert STIX IOCs to CSV format
    .DESCRIPTION
        Convert STIX to CSV format
        Supports JSON and XML files  
        Useful for immediately extracting all IOCS from a STIX file, for manual input to systems that don't support STIX JSON or XML
        Provides Ipv4, URL, FQDN, MD5, SHA, and SHA256 columns
    .PARAMETER Inputfile
        [Mandatory]
        The name of the STIX file that you want to read in
    .PARAMETER Outputfile
        The name of the file that you want the data to be written out to
    .PARAMETER View
        The type of IOC that you want displayed to the screen
        Can be any of the following values: ip, fqdn, url, md5, sha, or sha256
    .NOTES
        Author: Joel Ashman
        v0.1 - (2024-01-23) Initial version
        v0.2 - (2024-01-24) Added XML support, renamed function, removed filename and filesize from JSON conversion, added -view parameter to output to screen
    .EXAMPLE
        Convert-StixToCsv -Inputfile kruger.json -Outputfile smoothing.csv
        Convert-StixToCsv -Inputfile penske.xml -Outputfile material.csv -view fqdn
#>
    #requires -version 5    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$InputFile,
        [Parameter()]
        [string]$OutputFile,
        [Parameter()]
        [string]$View

    )

    # Build an array to store results in later
    $IndicatorArray = @()
    # Match files that end with the.json extension, Iterate through each object, ignore the non indicator objects, and parse out the relevant IOCs
    # Used Rons favourite (regex) to grab them, as it was easiest to use a capturing group for most, and pull them that way
    if ($InputFile -match ".*?\.json"){
        Write-Host -ForegroundColor Cyan "`nFile extension detected as JSON`n"
        $Data = (get-content $InputFile | ConvertFrom-Json).objects
        foreach ($Item in $Data){
            if ($Item.type -match "indicator"){
                $IndicatorObject = [PSCustomObject]@{
                    'type' = $Item.type
                    'subtype' = $Item.name.replace(" Indicator","")
                    'disposition' = $Item.indicator_types.replace("{","").replace("}","").replace("-activity","")
                    'ipv4' = [regex]::Match(($Item.pattern), "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").Groups.value
                    'md5' = $Md5 = [regex]::Match(($Item.pattern), "^.*?\.MD5\s\=\s\'([a-fA-F0-9]{32})\'").Groups[1].value
                    'sha' = [regex]::Match(($Item.pattern), "^.*?\.\'SHA\-1\'\s\=\s\'([a-fA-F0-9]{40})\'").Groups[1].value
                    'sha256' = [regex]::Match(($Item.pattern), "^.*?\.\'SHA\-256\'\s\=\s\'([a-fA-F0-9]{64})\'").Groups[1].value
                    'url' = [regex]::Match(($Item.pattern), "^\[url\:value\s\=\s'(.*?)'.*?$").Groups[1].value
                    'fqdn' = [regex]::Match(($Item.pattern), "domain\-name\:value\s\=\s\'(.*?)\'").Groups[1].value
                }
            }
            # Add the built object to the Array
            $IndicatorArray += $IndicatorObject
        }
    }
    # Match files that end with the.xml extension, Iterate through each object, ignore the non indicator objects, and parse out the relevant IOCs
    # Again, used Rons favourite (regex) to grab them, as it was easiest to use a capturing group for most, and pull them that way
    elseif ($InputFile -match ".*?\.xml"){
        Write-Host -ForegroundColor Cyan "`nFile extension detected as XML`n"
        $Xml = New-Object xml
        $Xml.load((Convert-Path "$($InputFile)"))
        $Data = $Xml.STIX_Package.Indicators.Indicator
        foreach ($Item in $doc.STIX_Package.Indicators.Indicator){
            $IndicatorObject = [PSCustomObject]@{
                'type' = "indicator"
                'subtype' = $Item.Title.replace("Malicious ","").replace(" Indicator","")
                'disposition' = ($Item.Title) -replace 'Malicious.*','Malicious'
                'ipv4' = $Item.Observable.Object.Properties.Address_Value."#text"
                'md5' = [regex]::Match(($Item.Observable.Object.Properties.Hashes.Hash.Simple_Hash_Value."#text"), "[a-fA-F0-9]{32}").Groups[0].value
                'sha' = [regex]::Match(($Item.Observable.Object.Properties.Hashes.Hash.Simple_Hash_Value."#text"), "[a-fA-F0-9]{40}").Groups[0].value
                'sha256' = [regex]::Match(($Item.Observable.Object.Properties.Hashes.Hash.Simple_Hash_Value."#text"), "[a-fA-F0-9]{64}").Groups[0].value
                'url' = [regex]::Match(($Item.Observable.Object.Properties.Value."#Text"), ".*\/.*").Groups[0].value
                'fqdn' = [regex]::Match(($Item.Observable.Object.Properties.Value."#Text"), "^(?!:\/\/)(?=.{1,255}$)((.{1,63}\.){1,127}(?![0-9]*$)[a-z0-9-]+\.?)$").Groups[0].value
            }
        # Add the built object to the Array
        $IndicatorArray += $IndicatorObject 
        }
    }
    else{
        Write-Host -ForegroundColor Red "Problem with input file. Only .json and .xml files are supported.  Exiting"
        Return
    }
    if ((-not $Outputfile) -and (-not $View)){
        Write-Host -ForegroundColor Red "No output chosen: no output file declared, and no selected IOC to display to screen. Exiting"
        Return
    }
    # If a value for the -view paramater has been given, display the results to the screen.  Sort the array and keep only unique values for that data type
    switch ($View){
        "fqdn"{($IndicatorArray | where-object subtype -eq "FQDN" | Where-object fqdn -ne "").fqdn | Sort-Object -unique}
        "url"{($IndicatorArray | where-object subtype -eq "Url" | Where-object url -ne "").url | Sort-Object -unique}
        "ip"{($IndicatorArray | where-object subtype -eq "IPv4" | Where-object ipv4 -ne "").ipv4 | Sort-Object -unique}
        "md5"{($IndicatorArray | where-object subtype -eq "File" | Where-object md5 -ne "").md5 | Sort-Object -unique}
        "sha"{($IndicatorArray | where-object subtype -eq "File" | Where-object sha -ne "").sha | Sort-Object -unique}
        "sha256"{($IndicatorArray | where-object subtype -eq "File" | Where-object sha256 -ne "").sha256 | Sort-Object -unique}
        default{
            Write-Host -ForegroundColor DarkYellow "-View parameter not recognised."
            if ($OutputFile){
                Write-Host -ForegroundColor Cyan "No -View Parameter, but CSV output will be written to $($OutputFile)"
            }
            else{Write-Host -ForegroundColor Red "No -View Parameter and no -OutputFile.  Nowhere to output data.  Exiting."}
        }

    }
    # Sort the array and keep only unique values.  All properties have to be examined, otherwise -Unique disposes of most of the data
    try{
        if ($Outputfile){
            $IndicatorArray | Sort-Object -Property type, subtype, disposition, ipv4, md5, sha, sha256, filename, filesize, url, fqdn -Unique | Export-Csv -Path $OutputFile -NoClobber -NoTypeInformation
            Write-host -ForegroundColor Cyan "File written to $($OutputFile)"
        }
    }
    catch{
        Write-Host -ForegroundColor Red "Couldn't write the CSV file for some reason. Exiting"
        Return
    }
}
