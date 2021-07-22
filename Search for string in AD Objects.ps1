# Looks for interesting strings (as well as IP addresses) in all AD objects.
# No dependencies, no special permissions (any authenticated user)
# v1.0
# comments to yossis@protonmail.com

param (
    [cmdletbinding()]
    [string]$SearchTerm,
    [switch]$ShowMatchDetails,
    [Switch]$OutputToGrid,
    [switch]$SearchForIPAddresses,
    [String]$OutputFile = "$(Get-Location)\SearchStringsInAD_$(Get-Date -Format ddMMyyyyHHmmss).txt"
)

function Switch-Color {
    if ($global:Color -eq "Yellow") {$global:Color = "Cyan"} else {$global:Color = "Yellow"};
    return $global:Color
}

$global:Color = "Yellow";
if ($SearchTerm)
    {
        if ($SearchForIPAddresses)
            {
                "Results for SearchTerm $SearchTerm + IPv4 addresses matching -" | out-file $OutputFile -append -force
            }
        else
            {
                "Results for SearchTerm $SearchTerm -" | out-file $OutputFile -append -force
            }
    }

else
    {
        if ($SearchForIPAddresses)
            {
                "Results for IPv4 addresses matching -" | out-file $OutputFile -append -force
            }
    else   
        {
            Write-Host "Missing SearchTerm parameter." -ForegroundColor Yellow;
            break
        }
}

if ($OutputToGrid)
    {
        $GridData = @();
        $GridData += "SamAccountName;Name;DistinguishedName;Attribute;Value (Match Details)"
    }

$DS = new-object system.directoryservices.directorysearcher;
$DS.Filter = '(WhenCreated=*)';
$DS.SizeLimit = 100000;
$DS.PageSize = 100000;

$DS.FindAll() | Foreach-Object {
        $obj = $_;
        $prop = $obj.properties.PropertyNames;

        $prop[0] | ForEach-Object {
                    $CurrentProp = $_;
                    
                    if ($SearchForIPAddresses)
                        {
                            $IPRegExResult = ([regex]::Matches($obj.Properties.$CurrentProp,"\b(?:\d{1,3}\.){3}\d{1,3}\b")).value;
                            $IPs = ($IPRegExResult | ForEach-Object {[System.Net.IPAddress]$_}).IPAddressToString;

                            # match by either SearchTerm or IP Address
                            if ($SearchTerm) 
                                {
                                    if ($obj.Properties.$CurrentProp -like "*$SearchTerm*" -or $IPs) 
                                        {
                                            $ResultMatch = $true
                                        }
                                }
                            # match by IP Address only (search term is empty)
                            elseif ($IPs) 
                                        {
                                            $ResultMatch = $true
                                        }
                        }
                    # match by search term only
                    elseif ($obj.Properties.$CurrentProp -like "*$SearchTerm*") {
                            $ResultMatch = $true;
                        }

                    if ($ResultMatch)
                        {
                            if ($ShowMatchDetails)
                                {
                                    Write-Host "Found match on attribute <$($CurrentProp)> of object:`n$($obj.properties.samaccountname); $($obj.properties.distinguishedname)`nMatch Details: $($obj.properties.$CurrentProp)" -ForegroundColor $(Switch-Color);
				                    "Found match on attribute <$($CurrentProp)> of object:`n$($obj.properties.samaccountname); $($obj.properties.distinguishedname)`nMatch Details: $($obj.properties.$CurrentProp)`n" | out-file $OutputFile -append -force;
                                }
                            else
                                {
                                    Write-Host "Found match on attribute <$($CurrentProp)> of object:`n$($obj.properties.samaccountname); $($obj.properties.distinguishedname)" -ForegroundColor $(Switch-Color);
				                    "Found match on attribute <$($CurrentProp)> of object:`n$($obj.properties.samaccountname); $($obj.properties.distinguishedname)`n" | out-file $OutputFile -append -force;
                                }

                            if ($OutputToGrid)
                                {
                                    $GridData += "$($obj.properties.samaccountname);$($obj.properties.name);$($obj.properties.distinguishedname);$CurrentProp;$($obj.properties.$CurrentProp)"
                                }
                            
                            # reset result match for the next loop
                            $ResultMatch = $false;
                        }
        }                               
}

if ($OutputToGrid)
    {
        $GridData | ConvertFrom-Csv -Delimiter ";" | Out-GridView -Title "Results for $SearchTerm"
    }

if ([io.file]::ReadAllLines($OutputFile).count -eq 1)
    {
        Write-Host "No matches found." -ForegroundColor Yellow
    }
else
    {
        Write-Host "`nResults saved to $OutputFile." -ForegroundColor Green
    }