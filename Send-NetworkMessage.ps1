function Send-NetworkMessage {
<#
.SYNOPSIS
    Notify users over the network (some fun with msg.exe automation)
    Author: Y1nTh35h311 (yossis@protonmail.com, #Yossi_Sassi)
    Version: 1.0.0
    License: BSD 3-Clause
    Required Dependencies: None (LoTL binary msg.exe)
    Optional Dependencies: None
#>

param (
    [cmdletbinding()]
    [parameter(mandatory=$true)]
    [string[]]$ComputerName,
    [string]$Message = "Please log off from your Pea-Sea",
    [int]$SecondsToDisplayMessage = 60
)

$ComputerName | ForEach-Object {
    $comp = $_;
    $sessionID = "";

    while ($sessionID -eq "")
        {
            Write-Host "Enumerating active sessions on $($comp.ToUpper())..." -ForegroundColor Cyan
            (qwinsta /server:$comp | Select-String active).ToString().Replace("Active","").Replace("console","")
            if (!$?) {break}
            Write-Host "Please choose & type session ID for $($comp.ToUpper()):" -ForegroundColor Green
            $sessionID = Read-Host
        }

    $x = New-Variable -Name "cmd_$($comp)" -PassThru
    $x.Value = Start-Process cmd.exe -ArgumentList "/c msg $sessionID /Server:$comp /time:$SecondsToDisplayMessage /v /w $Message" -WindowStyle Hidden -PassThru
    #Send-RDUserMessage -HostServer $comp -UnifiedSessionID $sessionID -MessageTitle $Title -MessageBody $Message	
    }

    # wait for msg sessions to terminate
    while (Get-Variable cmd_* | foreach { $_.Value.HasExited} | Select-String "False") {
            Write-Host "waiting for msg sessions to terminate... (can press ctrl+c to exit)" -ForegroundColor Cyan;
            Get-Variable cmd_* | select @{n='ComputerName';e={$_.name.ToString().Replace("cmd_","").ToUpper()}}, @{n='ID';e={$_.value.ID}}, @{n='MessageActiveOnDesktop';e={if ($_.value.HasExited) {"False"} else {"True"}}} | Format-Table
            sleep -Seconds 1; cls;
        }

    Write-Host "Done." -ForegroundColor Green
    Get-Variable cmd_* | select @{n='ComputerName';e={$_.name.ToString().Replace("cmd_","").ToUpper()}}, @{n='ID';e={$_.value.ID}}, @{n='MessageActiveOnDesktop';e={if ($_.value.HasExited) {"False"} else {"True"}}} | Format-Table
}
