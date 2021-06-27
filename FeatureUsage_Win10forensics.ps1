# Analyzing the FeatureUsage registry key can further validate findings with OTHER known forensic artifacts to help strengthen findings during an investigation. 
# This may also provide insight into the potential use of RDP, when it first occurred, and if anti-forensic techniques were employed by an actor to remove more well-known forensic artifacts, 
# or, in the case of a criminal investigation, it may provide some insight into user behavior and how they interact with Windows.

# comments: YossiS@protonmail.com (work in progress)

<# Additional more common artifects:
Shimcache
Prefetch
UserAssist
RecentApps
Last-Visited MRU
Windows Background Activity Moderator (BAM)
#>

$EAP = $ErrorActionPreference
$ErrorActionPreference = "silentlycontinue"

# 0. NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage
# Note: this key exists since Windows 10 ver 1903, circa ~2019
$keyFeatureUsage = 'hkcu:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage'

# 1. KeyCreationTime - determine when an account (any profile) first logged on interactively to that machine
$KeyCreationTime = [datetime]::FromFileTime($(Get-ItemProperty $keyFeatureUsage -name KeyCreationTime).KeyCreationTime)

"User first logged-on Interactively at $KeyCreationTime";
pause;

# Can/should do this for all users/profiles

# 2. AppBadgeUpdated:
# This key provides the number of times a running application has its badge icon updated (for example, to notify you of unread emails or notifications).
$title = "AppBadgeUpdated - Number of times a running application has its badge icon updated (e.g. notify unread emails)"

$AppBadgeUsage = Get-ItemProperty $keyFeatureUsage\AppBadgeUpdated

$IgnoreList = 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider','type GetType()','GetHashCode()','string ToString()'

$AppBadgeResults = @()
$AppBadgeUsage | Get-Member | select -ExpandProperty definition | % {$item=$_; $IgnoreList | % {if ($item -notlike "*$_*") {$item}}} | select -Unique | % {
        $Obj = New-Object psobject
        $App=$_.ToString().split("=")[0].replace("int ",'').Trim()
        [int]$NotificationCount = $_.ToString().split("=")[1].Trim()
        $Obj | Add-Member -Name App -MemberType NoteProperty -Value $App -Force
        $Obj | Add-Member -Name NotificationCount -MemberType NoteProperty -Value $NotificationCount -Force
        $AppBadgeResults += $Obj
    }

$AppBadgeResults | sort notificationCount -Descending | Out-GridView -Title $title

# 3. AppLaunch
# This key provides the number of times an application pinned to the taskbar was run
$title = "AppLaunch - Number of times an application pinned to the taskbar was run"

$AppLaunch = Get-ItemProperty $keyFeatureUsage\AppLaunch

$AppLaunchResults = @()
$AppLaunch | Get-Member | select -ExpandProperty definition | % {$item=$_; $IgnoreList | % {if ($item -notlike "*$_*") {$item}}} | select -Unique | % {
        $Obj = New-Object psobject
        $App=$_.ToString().split("=")[0].replace("int ",'').Trim()
        [int]$AppLaunchCount = $_.ToString().split("=")[1].Trim()
        $Obj | Add-Member -Name App -MemberType NoteProperty -Value $App -Force
        $Obj | Add-Member -Name PinnedToTaskBarLaunchCount -MemberType NoteProperty -Value $AppLaunchCount -Force
        $AppLaunchResults += $Obj
    }

$AppLaunchResults | sort PinnedToTaskBarLaunchCount -Descending | Out-GridView -Title $title

# 4. AppSwitched
# This key provides the number of times an application switched focus (was left-clicked on the taskbar)
$title = "AppSwitched - Number of times an application switched focus (was left-clicked on the taskbar)"

$AppSwitched = Get-ItemProperty $keyFeatureUsage\AppSwitched

$AppSwitchedResults = @()
$AppSwitched | Get-Member | select -ExpandProperty definition | % {$item=$_; $IgnoreList | % {if ($item -notlike "*$_*") {$item}}} | select -Unique | % {
        $Obj = New-Object psobject
        $App=$_.ToString().split("=")[0].replace("int ",'').Trim()
        [int]$AppSwitchedCount = $_.ToString().split("=")[1].Trim()
        $Obj | Add-Member -Name App -MemberType NoteProperty -Value $App -Force
        $Obj | Add-Member -Name AppSwitchedFocusLeftClickOnTaskBarCount -MemberType NoteProperty -Value $AppSwitchedCount -Force
        $AppSwitchedResults += $Obj
    }

$AppSwitchedResults | sort AppSwitchedFocusLeftClickOnTaskBarCount -Descending | Out-GridView -Title $title

# 5. ShowJumpView
# This key provides the number of times an application was right-clicked on the taskbar
$title = "AppRightClicked - Number of times an application was right-clicked on the taskbar"

$AppJumpView = Get-ItemProperty $keyFeatureUsage\ShowJumpView

$AppJumpViewResults = @()
$AppJumpView | Get-Member | select -ExpandProperty definition | % {$item=$_; $IgnoreList | % {if ($item -notlike "*$_*") {$item}}} | select -Unique | % {
        $Obj = New-Object psobject
        $App=$_.ToString().split("=")[0].replace("int ",'').Trim()
        [int]$AppJumpViewCount = $_.ToString().split("=")[1].Trim()
        $Obj | Add-Member -Name App -MemberType NoteProperty -Value $App -Force
        $Obj | Add-Member -Name AppJumpViewRightClickedOnTaskBarCount -MemberType NoteProperty -Value $AppJumpViewCount -Force
        $AppJumpViewResults += $Obj
    }

$AppJumpViewResults | sort AppJumpViewRightClickedOnTaskBarCount -Descending | Out-GridView -Title $title

# 6. TrayButtonClicked
# This key provides the number of times built-in taskbar buttons were clicked (e.g., clock, Start button, etc)
$title = "TrayButtonClicked - Number of times built-in taskbar buttons were clicked"

$AppTrayButtonClicked = Get-ItemProperty $keyFeatureUsage\TrayButtonClicked

$AppTrayButtonClickedResults = @()
$AppTrayButtonClicked | Get-Member | select -ExpandProperty definition | % {$item=$_; $IgnoreList | % {if ($item -notlike "*$_*") {$item}}} | select -Unique | % {
        $Obj = New-Object psobject
        $App=$_.ToString().split("=")[0].replace("int ",'').Trim()
        [int]$AppTrayButtonClickedCount = $_.ToString().split("=")[1].Trim()
        $Obj | Add-Member -Name App -MemberType NoteProperty -Value $App -Force
        $Obj | Add-Member -Name TrayButtonClickedCount -MemberType NoteProperty -Value $AppTrayButtonClickedCount -Force
        $AppTrayButtonClickedResults += $Obj
    }

$AppTrayButtonClickedResults | sort TrayButtonClickedCount -Descending | Out-GridView -Title $title

# 7. ShowJumpView - user interacted with app / clicked
$title = "ShowJumpView - Number of times a user interacted/clicked with a running application (fairly NEW in win10)"

$ShowJumpView = Get-ItemProperty $keyFeatureUsage\ShowJumpView

$IgnoreList = 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider','type GetType()','GetHashCode()','string ToString()'

$ShowJumpViewResults = @()
$ShowJumpView | Get-Member -MemberType NoteProperty | select -ExpandProperty Definition | % {$item=$_; $IgnoreList | % {if ($item -notlike "*$_*") {$item}}} | select -Unique | % {
        $Obj = New-Object psobject
        $App=$_.ToString().split("=")[0].replace("int ",'').Trim()
        [int]$InteractionCount = $_.ToString().split("=")[1].Trim()
        $Obj | Add-Member -Name App -MemberType NoteProperty -Value $App -Force
        $Obj | Add-Member -Name InteractionCount -MemberType NoteProperty -Value $InteractionCount -Force
        $ShowJumpViewResults += $Obj
    }

$ShowJumpViewResults | sort InteractionCount -Descending | Out-GridView -Title $title

$ErrorActionPreference = $EAP
