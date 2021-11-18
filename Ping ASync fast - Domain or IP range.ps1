## FAST(!) ping Async - for Domain-wide & non-domain networks ##
# Done with pure 'living off the land' mindset - no dependencies/Modules needed. sadly needs SendPingAsync in .net to properly powershell v2.0+.
# Comments to yossis@protonmail.com (1nTh35h311)

# Since powershell v2.0 (default of Windows 7/2008R2) misses needed .net Types and methods, separate methods are used for PSv2.0 vs. Other Windows PowerShell versions
if ($PSVersionTable.PSVersion.Major -eq 2)
    {
        "Missing supported .net methods to run Ping async. Consider running again from Powershell version greater than 2.0. Quiting.";
        Exit;
}

# get my current ipv4 addresses, excluding APIPA
$IPRange = @();
$i = (ipconfig.exe | Select-String IPv4 | Where {$_ -notlike "*169.254.*"}) | foreach { 
        $splitIP = $_.ToString().Split(":")[1].Trim().Split("."); 
        $ThreeOctets="$($splitIP[0]).$($splitIP[1]).$($splitIP[2])";
        $IPRange += $ThreeOctets;
        Clear-Variable ThreeOctets, splitIP
    }

# See if running from a domain-joined host or not
$Role = Get-WmiObject -Class Win32_ComputerSystem | select -ExpandProperty DomainRole;

# I don't really use this field, for now, just more as indication if to run domain-based hosts query in LDAP
switch ($Role){
	0 { $ComputerRole = "Standalone Workstation" }
	1 { $ComputerRole = "Member Workstation" }
	2 { $ComputerRole = "Standalone Server" }
	3 { $ComputerRole = "Member Server" }
	4 { $ComputerRole = "Domain Controller" }
	5 { $ComputerRole = "Domain Controller" }
	default { $ComputerRole = "Information not available" }
}

$DomainRoles = 1,3,4,5;

if ($DomainRoles -contains $Role) {
        "Running on $ComputerRole (Domain identified)`n";
        $Domain = ([adsi]'').name.ToString().ToUpper();
        $Option = Read-Host "Domain Or IP Range?`n1=Domain <$Domain>`n2=Current host's IP Range <$IPRange .1..254>`n3=Other IP Range`n";
    }
else
    {
        "No Domain identified (Running on $ComputerRole)`n";
        $Option = Read-Host "Domain Or IP Range?`n1=Domain <N/A from this host - Ignore>`n2=Current host's IP Range <$IPRange .1..254>`n3=Other IP Range`n";
    }

switch ($Option)
    {
        # Domain
        1 {
            # get all enabled Computer accounts from the currently connected AD domain
            if ($DomainRoles -contains $Role) {
                    $s = New-Object System.DirectoryServices.DirectorySearcher; $s.PageSize=100000; $s.Filter='(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))';
                    $HostsToCheck = $s.FindAll().Properties.name;
                }
                else
                {
                    "Invalid choice. Quiting."; 
                    exit;
                }
           }

        # current IP range
        2 {
            if ($($IPRange.Count) -eq 1)
                {
                    $HostsToCheck = 1..254 | % {"$IPRange.$_"};
                }
            else
                {
                    [int]$count = 0;
                    $Options = $IPRange | ForEach-Object {"$count - $_`n";$count++}
                    [int]$OptionIP = Read-Host "Choose from current host's IP Range`n$Options`n";
                    $HostsToCheck = 1..254 | % {"$($IPRange[$OptionIP]).$_"};
                }
           }

        # other IP range
        3 {
            $IPRangeInput = Read-Host "Enter IP Range to scan in format of x.x.x, e.g. 10.0.0";
            $HostsToCheck = 1..254 | % {"$IPRangeInput.$_"};
           }

        default {"Unknown choice. Quiting."; exit}
}

# silence unrelevant errors that might arrive from the loops ahead
$EAP = $ErrorActionPreference;
$ErrorActionPreference = "Silentlycontinue";

"Checking $($HostsToCheck.count) IPs..."

## for Newer PowerShell versions than 2.0
# CAN CHANGE THIS ping timeout to be much less or perhaps more?
$TimeOutInMiliSeconds = 200;

$PingResults = $HostsToCheck | foreach {(New-Object System.Net.NetworkInformation.Ping).SendPingAsync($_,$TimeOutInMiliSeconds)};
[Threading.Tasks.Task]::WaitAll($PingResults);
# Get IPs only where Success
$SuccessIPs = ($PingResults.Result | where Status -eq Success | Select -ExpandProperty address).IPAddressToString;
"First iteration method found $($SuccessIPs.count) responding IPs."

## Better try AT LEAST twice! MIGHT HAVE MISSED FEW IPs, as of the nature of this Async operation

## Another option to PingAsync with .net
# https://gist.github.com/guitarrapc/5eba8a5467c26663c9b8
$asm = "System", "System.Net", "System.Linq", "System.Threading.Tasks", "System.Net.NetworkInformation"
$source = @"
using System;
using System.Net;
using System.Threading.Tasks;
using System.Linq;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace PingEx
{
public class DnsResponse
{
    public string HostName { get; private set; }
    public IPAddress IPAddress { get; private set; }

    public DnsResponse(string hostName, IPAddress ip)
    {
        this.HostName = hostName;
        this.IPAddress = ip;
    }
}

public class DnsResolver
{
    public static DnsResponse ResolveIP(IPAddress ip, TimeSpan timeout)
    {
        Func<IPAddress, IPHostEntry> callback = s => Dns.GetHostEntry(s);
        var result = callback.BeginInvoke(ip, null, null);
        if (!result.AsyncWaitHandle.WaitOne(timeout, false))
        {
            return new DnsResponse(ip.ToString(), ip);
        }
        var hostEntry = callback.EndInvoke(result);
        return new DnsResponse(hostEntry.HostName, ip);
    }

    public static DnsResponse ResolveHostName(string hostNameOrAddress, TimeSpan timeout)
    {
        Func<string, IPHostEntry> callback = s => Dns.GetHostEntry(s);
        var result = callback.BeginInvoke(hostNameOrAddress, null, null);
        if (!result.AsyncWaitHandle.WaitOne(timeout, false))
        {
            return new DnsResponse(hostNameOrAddress, null);
        }
        var hostEntry = callback.EndInvoke(result);
        var ip = hostEntry.AddressList.FirstOrDefault(x => x.AddressFamily == AddressFamily.InterNetwork);
        return new DnsResponse(hostNameOrAddress, ip);
    }
}

public class PingResponse
{
    public string HostNameOrAddress { get; set; }
    public IPAddress IPAddress { get; set; }
    public IPStatus Status { get; set; }
    public bool IsSuccess { get; set; }
    public long RoundTripTime { get; set; }
    public bool IsResolved { get; set; }
}

public class NetworkInformationExtensions
{
    private static readonly byte[] _buffer = new byte[16];
    private static readonly PingOptions _options = new PingOptions(64, false);
    private static readonly TimeSpan _pingTimeout = TimeSpan.FromMilliseconds(10);
    private static readonly TimeSpan _dnsTimeout = TimeSpan.FromMilliseconds(20);
    private static bool _resolveDns = true;
    
    public static async Task<PingResponse[]> PingAsync(string[] hostNameOrAddress)
    {
        return await PingAsync(hostNameOrAddress, _pingTimeout, _resolveDns, _dnsTimeout);
    }

    public static async Task<PingResponse[]> PingAsync(string[] hostNameOrAddress, TimeSpan pingTimeout)
    {
        return await PingAsync(hostNameOrAddress, pingTimeout, _resolveDns, _dnsTimeout);
    }

    public static async Task<PingResponse[]> PingAsync(string[] hostNameOrAddress, bool resolveDns)
    {
        return await PingAsync(hostNameOrAddress, _pingTimeout, resolveDns, _dnsTimeout);
    }

    public static async Task<PingResponse[]> PingAsync(string[] hostNameOrAddress, TimeSpan pingTimeout, bool resolveDns)
    {
        return await PingAsync(hostNameOrAddress, pingTimeout, resolveDns, _dnsTimeout);
    }

    public static async Task<PingResponse[]> PingAsync(string[] hostNameOrAddress, TimeSpan pingTimeout, TimeSpan dnsTimeout)
    {
        return await PingAsync(hostNameOrAddress, pingTimeout, _resolveDns, _dnsTimeout);
    }

    private static async Task<PingResponse[]> PingAsync(string[] hostNameOrAddress, TimeSpan pingTimeout, bool resolveDns, TimeSpan dnsTimeout)
    {
        var pingResult = await Task.WhenAll(hostNameOrAddress.Select(async x =>
        {
            // Resolve only when incoming is HostName.
            IPAddress ip = null;
            DnsResponse resolve = null;
            var isIpAddress = IPAddress.TryParse(x, out ip);
            if (!isIpAddress)
            {
                resolve = DnsResolver.ResolveHostName(x, dnsTimeout);
                ip = resolve.IPAddress;
            }

            // Execute PingAsync
            PingReply reply = null;
            using (var ping = new Ping())
            {
                try
                {
                    reply = await ping.SendPingAsync(ip, (int)pingTimeout.TotalMilliseconds, _buffer, _options);
                }
                catch
                {
                    // ping throw should never stop operation. just return null.
                }
            }

            // set RoundtripTime
            long roundTripTime = 0;
            if (reply != null) roundTripTime = reply.RoundtripTime;

            // set Status
            var status = IPStatus.DestinationHostUnreachable;
            if (reply != null) status = reply.Status;

            // set IsSuccess
            var isSuccess = status == IPStatus.Success;

            // return when PingFailed || HostName || OmitResolveDns
            if (!isSuccess || !isIpAddress || !resolveDns)
                return new PingResponse
                {
                    HostNameOrAddress = x,
                    IPAddress = ip,
                    Status = status,
                    RoundTripTime = roundTripTime,
                    IsSuccess = isSuccess,
                    IsResolved = resolve != null,
                };

            // Resolve Dns only for success host entry.
            var host = x;
            resolve = DnsResolver.ResolveIP(ip, dnsTimeout);
            if (resolve != null) host = resolve.HostName;
            return new PingResponse
            {
                HostNameOrAddress = host,
                IPAddress = ip,
                Status = status,
                RoundTripTime = roundTripTime,
                IsSuccess = true,
                IsResolved = resolve != null,
            };
        }).ToArray());
        return pingResult;
    }
}
}
"@
Add-Type -TypeDefinition $source -ReferencedAssemblies $asm;
# [PingEx.NetworkInformationExtensions]::PingAsync($computerName).Result;
<#
measure-command {[PingEx.NetworkInformationExtensions]::PingAsync($HostsToCheck, [TimeSpan]::FromMilliseconds(1), $false).Result;} | select TotalMilliseconds
measure-command {[PingEx.NetworkInformationExtensions]::PingAsync($HostsToCheck, $false).Result;}
measure-command {[PingEx.NetworkInformationExtensions]::PingAsync($HostsToCheck, [TimeSpan]::FromMilliseconds(100), $false).Result;} | select TotalMilliseconds
measure-command {[PingEx.NetworkInformationExtensions]::PingAsync($HostsToCheck, [TimeSpan]::FromMilliseconds(10), [TimeSpan]::FromMilliseconds(10)).Result;} | select TotalMilliseconds
measure-command {[PingEx.NetworkInformationExtensions]::PingAsync($HostsToCheck).Result;} | select TotalMilliseconds
measure-command {[PingEx.NetworkInformationExtensions]::PingAsync($HostsToCheck, [TimeSpan]::FromMilliseconds(20), [TimeSpan]::FromMilliseconds(20)).Result;} | select TotalMilliseconds
measure-command {[PingEx.NetworkInformationExtensions]::PingAsync($HostsToCheck, [TimeSpan]::FromMilliseconds(20), [TimeSpan]::FromSeconds(1)).Result;} | select TotalMilliseconds
measure-command {[PingEx.NetworkInformationExtensions]::PingAsync($HostsToCheck, [TimeSpan]::FromSeconds(1), [TimeSpan]::FromSeconds(1)).Result;} | select TotalMilliseconds
measure-command {[PingEx.NetworkInformationExtensions]::PingAsync($HostsToCheck, [TimeSpan]::FromSeconds(2), [TimeSpan]::FromSeconds(1)).Result;} | select TotalMilliseconds
measure-command {[PingEx.NetworkInformationExtensions]::PingAsync($HostsToCheck, [TimeSpan]::FromSeconds(1), [TimeSpan]::FromSeconds(2)).Result;} | select TotalMilliseconds
#>

$IPs = ([PingEx.NetworkInformationExtensions]::PingAsync($HostsToCheck, [TimeSpan]::FromMilliseconds(1), $false).Result | Where-Object IsSuccess -eq "True").ipaddress.IPAddressToString;
"Second iteration method found $($IPs.count) responding IPs.";

<# NOTE: can also consider using this function (eventually, pingAsync as well..)
Function global:Invoke-KingPong{
#.Synopsis
#   King Pong - The Ping Kong...
#.DESCRIPTION
#   Power Ping: Multi-NIC/Auto-Subnet/Multi-Thread.
#   Returns only IPs where Success.
#   Inspired by a tweet from @Lee_Holmes.
#.LINK
#   https://twitter.com/Lee_Holmes/status/646890380995067904
    [CmdletBinding()]
    [Alias('Pong')]
    Param()
    Begin{
        ## Subs
        # IP to Num
        function IP2NUM{Param([String]$IP); return [int64]([int64]$IP.split(".")[0]*16777216+[int64]$IP.split(".")[1]*65536+[int64]$IP.split(".")[2]*256+[int64]$IP.split(".")[3])} 
        # Num to IP
        function NUM2IP{Param([Int64]$Num); return (([math]::truncate($Num/16777216)).tostring()+"."+([math]::truncate(($Num%16777216)/65536)).tostring()+"."+([math]::truncate(($Num%65536)/256)).tostring()+"."+([math]::truncate($Num%256)).tostring())}
        ## Prep
        # Prep empty IP list
        $IPList = @()
        # Get NICs
        $NICList = Gwmi win32_networkadapterconfiguration | Where defaultIPGateway -ne $null
        }
    Process{
        # List IPs to Ping
        Foreach($NIC in $NICList){
            # IP & Mask
            $IP   = [Net.IPAddress]::Parse($NIC.ipaddress[0])
            $Mask = [Net.IPAddress]::Parse($NIC.ipsubnet[0])
            # Network & Broadcast
            $Ntwrk  = New-Object net.IPAddress ($Mask.address -band $IP.address)
            $Brdcst = New-Object Net.IPAddress ([Net.IPAddress]::parse("255.255.255.255").address -bxor $Mask.address -bor $Ntwrk.address)
            Write-Verbose "$($Ntwrk.IPAddressToString) / $Mask" 
            # Start & End
            $Start = (IP2NUM -IP $ntwrk.ipaddresstostring)  +1
            $End   = (IP2NUM -IP $brdcst.ipaddresstostring) -1
            # Add IPs to IPList
            For($n=$Start; $n -le $End; $n++){$IPList += NUM2IP -Num $n}
            }
        # Ping IP List
        $Ping = $IPList | sort -Unique | %{(New-Object Net.NetworkInformation.Ping).SendPingAsync($_,250)}
        [Threading.Tasks.Task]::WaitAll($Ping) 
        # Get IPs where Success
        $Success = ($Ping.Result | ? Status -eq Success | Select -ExpandProp address).IPAddressToString
        Write-Verbose "Success: $($Success.count) / $($Ping.Result.count)"
        }
    End{return $Success}
    } 
#>

# Combine outputs from BOTH methods for ideal results
$IPs += $SuccessIPs; $IPs = $IPs | Where-Object {$_ -match '(\d{1,3}\.){3}\d{1,3}'} | select -Unique;
if ($($SuccessIPs.count) -ge 1)
	{
		Write-Host "Total of $($SuccessIPs.count) unique responding IPv4 addresses found." -ForegroundColor Cyan;
	}
else
	{
		Write-Host "Couldn't find responding IPv4 addresses. Quiting." -ForegroundColor Cyan;	
		Exit;
	}

## Get back list of Computer names
Write-Host "Attempting to resolve IP to hostname from responding IP(s)..." -ForegroundColor Cyan;

# first, we'll use a quicker Foreach function, to speed up the pipeline work
# function shared from https://powershell.one/
function Foreach-ObjectFast
{
  param
  (
    [ScriptBlock]
    $Process,
    
    [ScriptBlock]
    $Begin,
    
    [ScriptBlock]
    $End
  )
  
  begin
  {
    # construct a hard-coded anonymous simple function from
    # the submitted scriptblocks:
    $code = @"
& {
  begin
  {
    $Begin
  }
  process
  {
    $Process
  }
  end
  {
    $End
  }
}
"@
    # turn code into a scriptblock and invoke it
    # via a steppable pipeline so we can feed in data
    # as it comes in via the pipeline:
    $pip = [ScriptBlock]::Create($code).GetSteppablePipeline()
    $pip.Begin($true)
  }
  process 
  {
    # forward incoming pipeline data to the custom scriptblock:
    $pip.Process($_)
  }
  end
  {
    $pip.End()
  }
}

$Results = $IPs | Foreach-ObjectFast -process {$_+",$((([system.net.dns]::GetHostEntry($_))).hostname)"};
$Results;

if ($Results.Count -ge 1)
    {
        $File = "RespondingIPAddresses_$(Get-Date -Format ddMMyyyyHHmmss).csv";
        $ExportedResults = @(); $ExportedResults += "IP,Hostname"; $ExportedResults += $Results;
        $ExportedResults | Out-File $File;

        Write-Host "Results saved to $File." -ForegroundColor Cyan;
    }

$ErrorActionPreference = $EAP;
Clear-Variable IPRange, IPs, HostsToCheck, SuccessIPs;