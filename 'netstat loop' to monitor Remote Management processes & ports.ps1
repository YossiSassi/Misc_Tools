﻿# one-liner to monitor RPC/RDP/WinRM connections (can be edited of course to add more, or all ports)
while ($true) {Get-NetTCPConnection | where {$_.RemotePort -eq 135 -or $_.remoteport -ge 49152 -or $_.RemotePort -eq 5985 -or $_.RemotePort -eq 3389} | ? RemoteAddress -ne "127.0.0.1" | select localport,remoteaddress, @{n='RemoteComputerName';e={(Resolve-DnsName $_.RemoteAddress).namehost}}, remoteport,state,@{n='ProcessName';e={ (ps -id $_.OwningProcess).name}},@{n='ProcessUpTime';e={$t= (get-date) - (ps -id $_.OwningProcess).StartTime;"$($t.Hours):$($t.Minutes)";Clear-Variable t}}, @{n='PID';e={$_.OwningProcess}} | ft -AutoSize; sleep 1;cls}