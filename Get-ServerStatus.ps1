function Get-ServerStatus {
<#
.SYNOPSIS
    Gathers various info on remote systems

.DESCRIPTION
    Probably more complicated than it needs to be. But this script with loop through each of the
    listed systems and create a job to analyze that system. Inside the job, another job is created
    to check if WMI is running or not.

.PARAMETER ComputerName
    String[]. Computer name or list of computer names. Can also be sent from the pipe.

.PARAMETER ADServer
    String[]. Name of AD DC to scan

.PARAMETER NoPing 
    Switch. If enabled, the function will skip over the test connection. 

.PARAMETER Log
    The Log parameter is used to indicate that the function should produce logging output. The valid parameter values for the Log parameter are ToScreen, ToScreenAndFile, and ToFile. This will display logging on the screen only, on the screen and in a locally stored file, or in a locally stored file only, respectively.

.EXAMPLE
    This example ...
    PS > <Example>
    
.NOTES
    Name: Get-ServiceStatus
    Author: Loren Garth
    Comments: --
    Last Edit: 09/10/2019 [1.1]
    Template Version: 2.1 (Template Author: Tommy Maynard)
        - Doesn't log parameter value(s), if a parameter name includes the word "password."
    Version 1.0
        - Initial version
    Version 1.1
        - Converted WMI check to job based
        - Added uptime, AV status, reboot, and service checks 
        - Removed Ping as a job, it was just wasting resources
    Version 1.2
        - Added the ADServer Parameter to specify different domains
    To-Do:
        - Increase speed in which jobs are started
        - Add parameters to specify which checks to do
        - Add ability to specify domains
        - Integrate WMI check with the first pull? (Maybe not)
        - Create timeout parameters
#>
    [CmdletBinding()]
    param(
        # Add additional parameters here.

        #region Template code for Param block.
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ComputerName,

        [Parameter()]
        [string]$includeOS = "server",

        [Parameter()]
        [string]$ADServer,

        [Parameter()]
        [switch]$NoPing,

        [Parameter()]
        [ValidateSet('ToFile','ToScreen','ToScreenAndFile')]
        [string]$Log
        #endregion
    ) # End Param

    begin {
        #region Template code for Begin block.

        #region Catch Verbose being used.
        if ($PSBoundParameters['Verbose']) {
            $Log = 'ToScreen'
        }
        #endregion

        #region Create Write-Verbose function, log directory, and log file.
        switch ($Log) {
            { $Log -eq 'ToScreen' } {
                #region Modify the VerbosePreference variable.
                $VerbosePreference = 'Continue'
                break
                #endregion
            }
            { $Log -eq 'ToFile' -or $Log -eq 'ToScreenAndFile' } {
                #region Determine the file log directory (according to $Environment).
                $LogDirectory = "$($MyInvocation.MyCommand.Name)"
                if ($Environment) {
                    $LogPath = "$env:SystemDrive\support\Logs\$LogDirectory\$($Environment.ToUpper())"
                } else {
                    $LogPath = "$env:SystemDrive\support\Logs\$LogDirectory"
                } # End If-Else.
                #endregion

                #region Create the file log directory (if needed).
                if (-not (Test-Path -Path $LogPath)) {
                    [System.Void](New-Item -Path $LogPath -ItemType Directory)
                } # End If.
                #endregion

                #region Create the log file path variable.
                $FileName = "$(Get-Date -Format 'DyyyyMMddThhmmsstt.fffffff').txt"
                $LogFilePath = "$LogPath\$FileName"
                #endregion

                #region Create Write-Verbose function.
                if ($Log -eq 'ToFile') {
                    function Write-Verbose {
                        param($Message)
                        "[$(Get-Date -Format G)]: $Message" | Out-File -FilePath $LogFilePath -Append
                    }

                } elseif ($Log -eq 'ToScreenAndFile') {
                    $VerbosePreference = 'Continue'
                    function Write-Verbose {
                        param($Message)
                        Microsoft.PowerShell.Utility\Write-Verbose -Message $Message
                        "[$(Get-Date -Format G)]: $Message" | Out-File -FilePath $LogFilePath -Append
                    }
                } # End If-ElseIf.
                #endregion
            }
            'default' {}
        } # End Switch.
        #endregion

        #region Write informational details.
        $BlockLocation = '[INFO   ]'
        Write-Verbose -Message "$BlockLocation Invoking the $($MyInvocation.MyCommand.Name) $($MyInvocation.MyCommand.CommandType) on $(Get-Date -Format F)."
        Write-Verbose -Message "$BlockLocation Invoking user is ""$env:USERDOMAIN\$env:USERNAME"" on the ""$env:COMPUTERNAME"" computer."
        if ($Log -eq 'ToFile' -or $Log -eq 'ToScreenAndFile') {
            Write-Verbose -Message "$BlockLocation Storing log file as ""$LogFilePath."""
        }
        foreach ($Parameter in $PSBoundParameters.GetEnumerator()) {
            if ($Parameter.Key -like '*password*') {
                Write-Verbose -Message "$BlockLocation Including the ""$($Parameter.Key)"" parameter without the parameter $(If ($Parameter.Value.Count -gt 1) {'values'} Else {'value'})."
            } else {
                Write-Verbose -Message "$BlockLocation Including the ""$($Parameter.Key)"" parameter with the ""$($Parameter.Value -join '","')"" $(If ($Parameter.Value.Count -gt 1) {'values'} Else {'value'})."
            }
        }
        #endregion

        #region Write block location. 
        $BlockLocation = '[BEGIN  ]'
        Write-Verbose -Message "$BlockLocation Entering the Begin block [$($MyInvocation.MyCommand.CommandType): $($MyInvocation.MyCommand.Name)]."
        #endregion

        #endregion

    } # End Begin.

    process {
        #region Template code for Process block.

        #region Write block location.
        $BlockLocation = '[PROCESS]'
        Write-Verbose -Message "$BlockLocation Entering the Process block [$($MyInvocation.MyCommand.CommandType): $($MyInvocation.MyCommand.Name)]."
        #endregion

        #region AD Scan - Gather system names and IPs
        if ($ComputerName -eq $null) {

            # Grab all AD computer objects
            if ($ADServer) {
                $ADComputerList = Get-ADComputer -Server "$ADServer" -Filter * -Property Name,IPv4Address,OperatingSystem
            }
            else {
                $ADComputerList = Get-ADComputer -Filter * -Property Name,IPv4Address,OperatingSystem
            }
            # Future options:  Name,Description,Enabled,IPv4Address,LastLogonDate,OperatingSystem,OperatingSystemVersion,PasswordExpired,PasswordLastSet

            # Apply filter
            $ADComputerList = $ADComputerList | Where-Object { $_.OperatingSystem -match $includeOS }

            $computerList =
            foreach ($ADComputer in $ADComputerList) {
                $output = [ordered]@{
                    'ComputerName' = $null
                    'IPAddress' = $null
                    'Pingable' = $null
                    'WMI' = $null
                }

                $output.ComputerName = $ADComputer.Name
                # Set IP address from AD or resolve it in DNS

                if ($ADComputer.IPv4Address) {
                    $output.IPAddress = $ADComputer.IPv4Address
                }
                else {
                    try {
                        $output.IPAddress = (Resolve-DnsName -Name $ADComputer.Name -Type A -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
                    }
                    catch {
                        Write-Verbose -Message "Cant resolve $Computer $PSItem"
                    }
                }
                [pscustomobject]$output
            }
        }

        #endregion

        #region Non-AD Scan - Gather system names and IPs
        else {
            $computerList =
            foreach ($Computer in $ComputerName) {
                $output = [ordered]@{
                    'ComputerName' = $null
                    'IPAddress' = $null
                    'Pingable' = $null
                    'WMI' = $null
                }

                Write-Verbose -Message "1"
                #Check for valid IP address
                if ($Computer -as [IPAddress] -as [bool]) {
                    $output.IPAddress = $Computer
                    try {
                        $output.ComputerName = (Resolve-DnsName -Name $Computer -Type A | Select-Object -First 1).NameHost
                    }
                    catch {
                        Write-Verbose -Message "Cant resolve $Computer to Name $PSItem"
                    }
                }

                # Else assume that $computer is the name
                else {
                    $output.ComputerName = $Computer

                    try {
                        $output.IPAddress = (Resolve-DnsName -Name $Computer -Type A | Select-Object -First 1).IPAddress

                    }
                    catch {
                        Write-Verbose -Message "Cant resolve $Computer to IP $PSItem"
                    }
                }

                [pscustomobject]$output
            }
        }
        #endregion

        #region Create jobs for each system on the list (Main loop)
        Write-Verbose -Message "$BlockLocation Preparing jobs for each system"
        foreach ($computer in $computerList) {

            # Prep work for submitting to a job
            $scriptBlock = {
                # Pass the parameter
                $computer = $args[0]
                $NoPing = $args[1]

                $output = [ordered]@{
                    'ComputerName' = $null
                    'IPAddress' = $null
                    'Pingable' = $null
                    'WMI' = $null
                }
                $output.ComputerName = $computer.ComputerName
                $output.IPAddress = $computer.IPAddress

                #region Ping the computer
                ### Can be cleaned up a bit. Move IP checks outside of block

                # Skip further checks if IP doesn't exit
                if ($output.IPAddress -as [IPAddress] -as [bool] -eq $false) {
                    Write-Verbose -Message "$computer is offline, skipping it."
                    $output.IPAddress = $null
                }
                if ($NoPing -eq $false -and $output.IPAddress) {
                    # Check if it's online, 1 ping
                    try
                    {
                        $output.Pingable = Test-Connection -ComputerName $output.IPAddress -Count 1 -Quiet
                    }
                    catch
                    {
                        $output.Pingable = "error"
                        Write-Verbose -Message "Ran into an issue with Test-Connection: $PSItem"
                    }
                }
                else {
                    $output.Pingable = "skipped"
                }

                #endregion

                #region Check WMI as a job

                # If computer is not pingable and NoPing hasn't been set, skip it.
                if ($output.Pingable -eq $true -or $NoPing -eq $true) {

                    # WMI call needs to be in it's own block to be able to use the Wait-Job -timeout
                    $WMIBlock = {
                        $computer = $args[0]
                        gwmi Win32_LogicalDisk -ComputerName $computer -Filter "DriveType=3"
                    }
                    $WMIJob = Start-Job -ScriptBlock $WMIBlock -ArgumentList $output.IPAddress -Name "WMI Check $($output.IPAddress)"
                    $WMIJob | Wait-Job -Timeout 7 | Out-Null
                    $output.WMI = $($WMIJob | Receive-Job) -as [bool]
                }
                #endregion 

                #region Get HDD info WMI Win32_LogicalDisk
                $output.Add('FreeSpace(GB)',$null)
                $output.Add('FreeSpace(%)',$null)

                if ($output.WMI) {
                    try {
                        # Gather all drive info
                        [pscustomobject]$WMIDrive = gwmi Win32_LogicalDisk -ComputerName $output.IPAddress -Filter "DriveType=3"
                        if ($WMIDrive) {
                            $output.'FreeSpace(GB)' =
                            foreach ($drive in $WMIDrive) {
                                ,@($drive.DeviceID,[math]::Round($drive.FreeSpace / 1GB,2))
                            }
                            # Sort it, if it's a multi dimensional array
                            if ($output.'FreeSpace(GB)'[0] -is [array]){
                                $output.'FreeSpace(GB)' = $output.'FreeSpace(GB)' | sort @{ Expression = { $_[1] }; Ascending = $true }                        
                            }
        
                            $output.'FreeSpace(%)' =
                            foreach ($drive in $WMIDrive) {
                                ,@($drive.DeviceID,$("{0:p2}" -f ($drive.FreeSpace / $drive.Size)))
                            }
                            # Sort it, if it's a multi dimensional array
                            if ($output.'FreeSpace(%)'[0] -is [array]){
                                $output.'FreeSpace(%)' = $output.'FreeSpace(%)' | sort @{ Expression = { $_[1] }; Ascending = $true }
                            }
                        }
                    }
                    catch {
                        Write-Verbose -Message "Failed to lookup HDD info on $computer"
                        $output.'FreeSpace(GB)' = 'error'
                        $output.'FreeSpace(%)' = 'error'
                    }
                }
                else {
                    $output.'FreeSpace(GB)' = 'skipped'
                    $output.'FreeSpace(%)' = 'skipped'
                }
                #endregion

                #region Get System Uptime WMI Win32_OperatingSystem
                $output.Add('Uptime',$null)

                if ($output.WMI) {

                    $UptimeBlock = {
                        $computer = $args[0]

                        # Pull the WMI info
                        $WMIData = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computer | Select-Object LocalDateTime,LastBootUpTime
                        # Calculate the difference
                        $uptime = [Management.ManagementDateTimeConverter]::ToDateTime($WMIData.LocalDateTime) - [Management.ManagementDateTimeConverter]::ToDateTime($WMIData.LastBootUpTime)
                        # Round to 2 decimals
                        [math]::Round($uptime.TotalDays,2)
                    }
                    $UptimeJob = Start-Job -ScriptBlock $UptimeBlock -ArgumentList $output.IPAddress -Name "Uptime Check $($output.IPAddress)"
                    $UptimeJob | Wait-Job -Timeout 10 | Out-Null
                    try {
                        $output.Uptime = $UptimeJob | Receive-Job
                    }
                    catch {
                        $output.Uptime = $null
                    }
                }
                else {
                    $output.Uptime = "skipped"
                }

                #endregion

                #region Get pending updates - disabled for now

                #$output.Add('UpdatesPending',$null)
                if ($output.WMI -and $false) {
                    $WMIUpdates = Get-WmiObject -ComputerName $output.IPAddress -Query "SELECT * FROM CCM_UpdateStatus" -Namespace "root\ccm\SoftwareUpdates\UpdatesStore"
                    $output.UpdatesPending = ($WMIUpdates | Where-Object { $_.status -eq "Missing" }).count
                } else {
                    #$output.UpdatesPending = "skipped"
                }
                #endregion

                #region Check for RebootPending from WMI Registry
                $output.Add('RebootPending',$null)

                if ($output.WMI) {
                    try {
                        # Remote registry through WMI ### maybe send as a job?
                        $WMIRegistry = Get-WmiObject -List "StdRegProv" -Namespace root\default -ComputerName $output.IPAddress

                        # Define registry locations
                        $HKLM = 2147483650
                        $RebootPendingKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"
                        $RebootRequiredKey = "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
                        $PendingFileRenameOperationsKey = "SYSTEM\CurrentControlSet\Control\Session Manager"

                        # Grab the info
                        $RebootPending = ($WMIRegistry.GetDWORDValue($HKLM,$RebootPendingKey,"RebootPending")).uValue -as [bool]
                        $RebootRequired = ($WMIRegistry.GetDWORDValue($HKLM,$RebootPendingKey,"RebootRequired")).uValue -as [bool]
                        $PendingFileRenameOperations = ($WMIRegistry.GetDWORDValue($HKLM,$PendingFileRenameOperationsKey,"PendingFileRenameOperations")).uValue -as [bool]

                        if ($RebootPending -or $RebootRequired -or $PendingFileRenameOperations) {
                            $output.RebootPending = "RebootPending: $RebootPending RebootRequired: $RebootRequired Rename: $PendingFileRenameOperations "
                        } else {
                            $output.RebootPending = $false
                        }
                    }

                    catch {
                        Write-Warning "Unable to access registry on $($output.IPAddress)!"
                        $output.RebootPending = "access error, run as admin?"
                    }
                }
                #endregion

                #region Get AV DAT date and version from WMI Registry
                $output.Add('McAfeeEng',$null)
                $output.Add('DATInfo',$null)
                $output.Add('Patch',$null)

                if ($output.WMI) {
                    try {

                        # Remote registry through WMI ### maybe send as a job?
                        $WMIRegistry = Get-WmiObject -List "StdRegProv" -Namespace root\default -ComputerName $output.IPAddress

                        $HKLM = 2147483650
                        $AVRegKey = "SOFTWARE\WOW6432Node\McAfee\AVEngine"
                        $VSERegKey = "SOFTWARE\WOW6432Node\McAfee\DesktopProtection"

                        $EngineVersionMajor = ($WMIRegistry.GetDWORDValue($HKLM,$AVRegKey,"EngineVersionMajor")).uValue
                        $EngineVersionMinor = ($WMIRegistry.GetDWORDValue($HKLM,$AVRegKey,"EngineVersionMinor")).uValue
                        $output. "McAfeeEng" = [string]$EngineVersionMajor + "." + [string]$EngineVersionMinor
                        $AvDatVersion = ($WMIRegistry.GetDWORDValue($HKLM,$AVRegKey,"AvDatVersion")).uValue
                        $AvDatDate = ($WMIRegistry.GetStringValue($HKLM,$AVRegKey,"AvDatDate")).sValue
                        $output. "DATInfo" = [string]$AvDatVersion + " : " + [string]$AvDatDate
                        $output. "Patch" = ($WMIRegistry.GetStringValue($HKLM,$VSERegKey,"CoreRef")).sValue
                    }

                    catch {
                        Write-Warning "Unable to access registry on $($output.IPAddress)!"
                        $output. "McAfeeEng" = "access error, run as admin?"
                    }
                }
                #endregion

                #region Look for stopped services WMI
                $output.Add('StoppedServices',$null)

                if ($output.WMI) {
                    try {
                        $output.StoppedServices = Get-WmiObject win32_service -Filter "StartMode = 'auto' AND state != 'running'" -ComputerName $output.IPAddress | ForEach-Object { $_.DisplayName }
                    }
                    catch {
                        $output.StoppedServices = $null
                    }

                }
                #endregion

                #region Get last GPUpdate - Disabled for now

                # $output.Add('LastGPUpdate',$null)
                if ($output.WMI -and $false) {
                    try {
                        $GPResult = GPResult.exe /S $output.IPAddress /SCOPE COMPUTER /R
                        # Cleanup
                        [string]$GPUpdate = $GPResult | Select-String -SimpleMatch "Last time Group Policy was applied"
                        $output.LastGPUpdate = $GPUpdate.TrimStart(" ").TrimStart("Last time Group Policy was applied: ")

                    }
                    catch {
                        $output.LastGPUpdate = "GPResult error"
                    }
                }
                #endregion

                # Finally cast it to PSCustomObject before output
                [pscustomobject]$output
            }

            # Start the job and pass it the $computer and $ping setting
            Write-Verbose -Message "$BlockLocation Starting job for $($computer.IPAddress)"
            Start-Job -ScriptBlock $scriptBlock -ArgumentList $computer,$NoPing -Name "Computer Status $($computer.IPAddress)" | Out-Null

        } # End foreach
        #endregion

        #region Return results as they finish
        # Loop and return jobs as they complete
        Write-Verbose -Message "$BlockLocation Waiting for tasks to finish"
        while (Get-Job -Name "Computer Status*") {
            # Clear out some of the completed jobs
            Get-Job -State Completed -HasMoreData $false | Remove-Job
            Get-Job -Name "Computer Status*" -HasMoreData $true | Receive-Job
            sleep 1
        }
        #endregion

        #endregion

    } # End Process.

    end {
        #region Template code for End block.
        #region Write block location.
        $BlockLocation = '[END    ]'
        Write-Verbose -Message "$BlockLocation Entering the End block [$($MyInvocation.MyCommand.CommandType): $($MyInvocation.MyCommand.Name)]."
        #endregion
        #endregion

        # Add additional code here.
    } # End End.
} # End Function: Get-StatusHDD.
