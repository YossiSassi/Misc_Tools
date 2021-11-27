# Find renamed accounts (New and old samaccountname)  - no dependencies / No AD module required. Permissions needed: 'Event Log Redears' or higher.
# comments to yossis@protonmail.com

$UserRenamedFilter = @'
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4781)]]</Select>
  </Query>
</QueryList>
'@

function Switch-Color {
    if ($global:Color -eq "Yellow") {$global:Color = "Cyan"} else {$global:Color = "Yellow"};
    return $global:Color
}

$global:Color = "Yellow";

$DS = New-Object System.DirectoryServices.DirectorySearcher;
$DS.Filter = "(&(objectCategory=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(primaryGroupID=516)))";
$DCs = $DS.FindAll().Properties.dnshostname # (Get-ADDomainController -Filter *).hostname

$Events = @(); 
[int]$i = 1;

$DCs | foreach {
    "Querying $_ ($i out of $($DCs.count))...";
    $Events += Get-WinEvent -ComputerName $_ -FilterXml $UserRenamedFilter -ErrorAction SilentlyContinue;
    $i++
}

if ($Events)
    {
        $Events | foreach {
            $xml = ([xml]$_.ToXml()).Event.EventData.Data;
            $PrevSAMaccName = $xml[0].'#text' # Old value
            $NewSAMaccName = $xml[1].'#text' # new/current(?) value value
            $Sid = $xml[3].'#text' # Target SID
            $RenamedBy = $xml[5].'#text' # renamed by
            $LogonID = $xml[7].'#text' # Session LogonID
            $datetime = $_.TimeCreated;
            Write-Host "Current account name:<$NewSAMaccName> <SID: $Sid>`nPrevious SamAccountName: <$PrevSAMaccName>`nRenamed by <$RenamedBy> on <$datetime> during LogonID <$LogonID>" -ForegroundColor $(Switch-Color)
        }
    }