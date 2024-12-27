# SetupStartupTask.ps1

# Function to get task info
function Get-Task-Info {
    $taskName = "InterruptModerationUsb"
    $taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName }
    return @{TaskExists = $taskExists; TaskName = $taskName}
}

function Apply-Startup-Script {
    $TaskInfo = Get-Task-Info
    if (!$TaskInfo.TaskExists) {
        $action = New-ScheduledTaskAction -Execute "powershell" -Argument "-WindowStyle hidden -ExecutionPolicy Bypass -File $PSScriptRoot\XHCI-IMOD-Disable.ps1 -IsStartupRun"
        $delay = New-TimeSpan -Seconds 5
        $trigger = New-ScheduledTaskTrigger -AtLogOn -RandomDelay $delay
        $UserName = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName
        $principal = New-ScheduledTaskPrincipal -UserID $UserName -RunLevel Highest -LogonType Interactive
        $STSet = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -WakeToRun -AllowStartIfOnBatteries
        Register-ScheduledTask -TaskName $($TaskInfo.TaskName) -Action $action -Trigger $trigger -Principal $principal -Settings $STSet
        [Environment]::NewLine
    }
}

# Function to remove startup script
function Remove-Startup-Script {
    $TaskInfo = Get-Task-Info
    if ($TaskInfo.TaskExists) {
        Unregister-ScheduledTask -TaskName $TaskInfo.TaskName -Confirm:$false
        Write-Host "Task '$($TaskInfo.TaskName)' has been removed from startup."
    } else {
        Write-Host "The task '$($TaskInfo.TaskName)' does not exist."
    }
}

# Main logic
$TaskInfo = Get-Task-Info
if ($TaskInfo.TaskExists) {
    Write-Host "The task '$($TaskInfo.TaskName)' already exists. Do you want to remove it?"
    $remove = Read-Host "[Y]es to remove, [N]o to keep"
    if ($remove -eq "Y") {
        Remove-Startup-Script
    }
} else {
    Write-Host "Do you wish to set this script to run automatically at every Windows startup?"
    $setup = Read-Host "[Y]es to setup, [N]o to cancel"
    if ($setup -eq "Y") {
        Apply-Startup-Script
    }
}
