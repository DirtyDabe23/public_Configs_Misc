function Clear-Enrollment{
    [CmdletBinding()]
    param(
        [String] $ComputerName,
        [switch] $InTune,
        [switch] $OfficeApps,
        [switch] $Reboot,
        [switch] $Message
    )

    $process = "AAD Enrollment"
    #Sets the PowerShell Window Title
    $host.ui.RawUI.WindowTitle = $process

    #Clears the Error Log
    $error.clear()


    #This WMI Query gets a ton of rich information about the endpoint
    $computerInfo = Get-ComputerInfo | select-object -Property *

    #File Creation Objects
    $shareLoc = "$env:Temp"
    $logFileName = "$($process).txt"
    $errorLogCSV = "$($process).csv"
    $dateTime = Get-Date -Format yyyy.MM.dd.HH.mm
    $exportPath = $shareLoc+$dateTime+"."+$logFileName
    $errorExportPath = $shareLoc+$dateTime+"."+$errorLogCSV
    Start-Transcript -Path $exportPath

    #Error Logging
    $errorLog = @()
    $errorDetails = $null


    #Log Timing For the Full Process Start
    $allStartTime = Get-Date 
    $currTime = Get-Date -format "HH:mm"
    Write-Output "[$($currTime)] | [$process] | Starting"





    if($InTune){
            ######################################################### FUNCTIONS START HERE#######################################################
        #Log Timing For Individual Functions and their standard function
        $procStartTime = Get-Date 
        $currTime = Get-Date -format "HH:mm"
        $procProcess = "Clearing Old Enrollments"
        Write-Output "[$($currTime)] | [$process] | [$procProcess] Starting"

        #Standard Try Catch Block
        Try
        {
            #get scheduled tasks 
            $regGuids = @()
            $Paths = Get-ScheduledTask -TaskPath \Microsoft\Windows\EnterpriseMgmt* | Select-Object TaskPath
            ForEach ($path in $paths)
            {
                $regGUIDS += $Path.TaskPath.Split("EnterpriseMgmt\")[1].trim("\")
            }
            Get-ScheduledTask -TaskPath "\Microsoft\InTune*" | Unregister-ScheduledTask -Confirm:$false

            #get the registration guids
            $regGuids = $regGuids | Select-Object -unique

            $removalPath = $paths.taskPAth | Select-Object -Unique


            #Remove the scheduled tasks, once the container is empty it self removes.
            ForEach ($path in $removalPath)
            {
                Get-ScheduledTask -taskpath $path | Unregister-ScheduledTask -confirm:$false
            }


            #Remove the Registry Keys
            ForEach ($guid in $regGuids)
            {
                $items = @()
                $items = "HKLM:\SOFTWARE\Microsoft\Enrollments\$guid",`
                "HKLM:\SOFTWARE\Microsoft\Enrollments\Status\$guid",`
                "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$guid" ,`
                "HKLM:\SOFTWARE\Microsoft\PolicyManager\AdmxInstalled\$guid",`
                "HKLM:\SOFTWARE\Microsoft\PolicyManager\Providers\$guid",`
                "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\$guid",`
                "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger\$guid",`
                "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions\$guid"


                ForEach ($item in $items)
                {
                    If (test-path $item)
                    {
                    Get-ITem -Path $item | Remove-Item -Force -Recurse
                    }
                }
            }
            #A few extra registry keys to remove in case they exist, specifically related to the device itself.
            if (Get-Item  -Path "$env:LocalAppData\Microsoft\Office\Licenses" -errorAction Ignore){Get-Item  -Path "$env:LocalAppData\Microsoft\Office\Licenses" | Remove-Item -Force -Recurse}
            If (Get-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing" -erroraction Ignore){Get-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing" | Remove-Item -Force -Recurse}
            If (Get-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Identity" -erroraction Ignore){Get-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Identity" | Remove-Item -Force -Recurse}
            If (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\MDMDeviceID" -ErrorAction Ignore){Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\MDMDeviceID" | Remove-Item -Force -Verbose}
            If (Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger" -ErrorAction Ignore){Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Logger" | Remove-Item -Force -Verbose}
            If (Get-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\MDM\" -ErrorAction Ignore){Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\MDM" | remove-Item -Force -Recurse}
            #This needs run in the users context, otherwise it will not remove their profile but the administrative accounts!
            If (Get-Process OneDrive -ErrorAction Ignore){Stop-Process -Name "OneDrive" -Force}
            If(Get-Item "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1" -errorAction Ignore){Get-Item "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"  | Remove-Item -Force -Recurse}
            


            #Remove the InTune Certificate
            If(Get-ChildItem "Cert:\LocalMachine\CA" | Where-Object {($_.subject -like 'CN=Microsoft Intune MDM Device CA')} -ErrorAction Ignore)
            {
                Get-ChildItem "Cert:\LocalMachine\CA" | Where-Object {($_.subject -like 'CN=Microsoft Intune MDM Device CA')} -ErrorAction Ignore | Remove-Item -Force -Verbose
            }


            If(Get-ChildItem "Cert:\LocalMachine\AAD Token Issuer\" -ErrorAction Ignore)
            {
                $oldTokenIssuers = Get-ChildItem "Cert:\LocalMachine\AAD Token Issuer\" -ErrorAction Ignore
                ForEach ($oldTokenIssuer in $oldTokenIssuers)
                {
                    Remove-Item -Path $oldTokenIssuer.psPath -Force -Recurse
                }
            }

            #This is the part of the script that leaves the tenant.
            Start-Process -FilePath "$env:SystemRoot\System32\dsregcmd.exe"  -argumentlist "/leave" -Wait -NoNewWindow -UseNewEnvironment

            #These are the functions that removes old user enrollment packages and old user accounts.
            $oldUserEnrollmentPackages = Get-Item -Path "$env:LocalAppData\Packages\Microsoft.AAD.BrokerPlugin*" -ErrorAction Ignore
            $currTime = Get-Date -format "HH:mm"
            Write-Output "[$($currTime)] | [$process] | [$procProcess] Removing Old User AAD Packages"

            while ($oldUserEnrollmentPackages)
            {
            $currTime = Get-Date -format "HH:mm"
            Write-Output "[$($currTime)] | [$process] | [$procProcess] Waiting for AAD Package Availability"
                ForEach ($oldUserEnrollmentPackage in $oldUserEnrollmentPackages)
                {
                    try{
                    Remove-Item -path $oldUserEnrollmentPackage -Force -Recurse -ErrorAction Stop
                    }
                    catch{
                        Start-Sleep -Seconds 5
                        Remove-Item -path $oldUserEnrollmentPackage -Force -Recurse -ErrorAction SilentlyContinue
                    }

                }
                $oldUserEnrollmentPackages = Get-Item -Path "$env:LocalAppData\Packages\Microsoft.AAD.BrokerPlugin*" -ErrorAction Ignore
            }
            
            #this removes WAM accounts as stated at this link: https://learn.microsoft.com/en-us/office/troubleshoot/activation/reset-office-365-proplus-activation-state#sectiona
            if(-not [Windows.Foundation.Metadata.ApiInformation,Windows,ContentType=WindowsRuntime]::IsMethodPresent("Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager", "FindAllAccountsAsync"))
            {
                throw "This script is not supported on this Windows version. Please, use CleanupWPJ.cmd."
            }

            Add-Type -AssemblyName System.Runtime.WindowsRuntime

            Function AwaitAction($WinRtAction) {
            $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and !$_.IsGenericMethod })[0]
            $netTask = $asTask.Invoke($null, @($WinRtAction))
            $netTask.Wait(-1) | Out-Null
            }

            Function Await($WinRtTask, $ResultType) {
            $asTaskGeneric = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
            $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
            $netTask = $asTask.Invoke($null, @($WinRtTask))
            $netTask.Wait(-1) | Out-Null
            $netTask.Result
            }

            $provider = Await ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager,Windows,ContentType=WindowsRuntime]::FindAccountProviderAsync("https://login.microsoft.com", "organizations")) ([Windows.Security.Credentials.WebAccountProvider,Windows,ContentType=WindowsRuntime])

            $accounts = Await ([Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager,Windows,ContentType=WindowsRuntime]::FindAllAccountsAsync($provider, "d3590ed6-52b3-4102-aeff-aad2292ab01c")) ([Windows.Security.Authentication.Web.Core.FindAllAccountsResult,Windows,ContentType=WindowsRuntime])

            $accounts.Accounts | ForEach-Object { AwaitAction ($_.SignOutAsync('d3590ed6-52b3-4102-aeff-aad2292ab01c')) }

            $FinalEnrollmentPackages = Get-ITem -Path "HKLM:\SOFTWARE\Microsoft\Enrollments\*"
            ForEach ($finalEnrollmentPackage in $FinalEnrollmentPackages)
            {
                $checkPackage = Get-ITem -Path $finalEnrollmentPackage.PSPath | Get-ItemProperty
                if ($checkPackage.UPN)
                {
                    Remove-Item -Path $finalEnrollmentPAckage.PSPath -recurse -Force
                }
            }
    }
        
        Catch
        {
            $errorDetails = $error[0] | Select-Object *
            $currTime = Get-Date -format "HH:mm"
            $errorLog += [PSCustomObject]@{
                processFailed                           = $procProcess
                timeToFail                              = $currTime
                reasonFailed                            = $errorDetails 
                failedTargetStandardName                = $computerinfo.CsName
                failedTargetSerialNumber                = $computerInfo.BiosSerialNumber
                failedTargetDNSName                     = $computerinfo.CsDNSHostName
                failedTargetUser                        = $computerInfo.CsUserName
                failedTargetWorkGroup                   = $computerInfo.CsWorkgroup
                failedTargetDomain                      = $computerInfo.CsDomain
                failedTargetOSOrganization              = $computerInfo.OsOrganization
                failedTargetChassis                     = $computerInfo.CsChassisSKUNumber
                failedTargetManufacturer                = $computerInfo.CsManufacturer
                failedTargetModel                       = $computerInfo.CsModel
                failedTargetTotalPhysicalMemory         = $computerInfo.CsTotalPhysicalMemory
                failedTargetPhysicallyInstalledMemory   = $computerInfo.PhysicallyInstalledMemory
                failedTargetOsFreePhysicalMemory        = $computerInfo.OsFreePhysicalMemory
                failedTargetOsFreeVirtualMemory         = $computerInfo.OsFreeVirtualMemory
                failedTargetOsInUseVirtualMemory        = $computerInfo.OsInUseVirtualMemory
                failedTargetProcessorName               = $computerInfo.CSProcessors.Name
                failedTargetProcessorSpeedMhz           = $computerInfo.CSProcessors.MaxClockSpeed
                failedTargetProcessorNumOfCores         = $computerInfo.CSProcessors.NumberofCores
                failedTargetProcessorNumOfThreads       = $computerInfo.CSProcessors.NumberOfLogicalProcessors
                failedTargetProcessorStatus             = $computerInfo.CSPRocessors.Status
                failedTargetPowerSupplyState            = $computerInfo.CSPowerSupplyState
                failedTargetThermalState                = $computerInfo.CSThermalState
                failedTargetBootState                   = $computerInfo.CsBootupState
                failedTargetOSVersion                   = $computerInfo.OSVersion
                failedTargetOSStatus                    = $computerInfo.OsStatus
                failedTargetUptime                      = $computerInfo.OsUptime
                failedTargetNumUsers                    = $computerInfo.OsNumberOfUsers
                failedTargetTimezone                    = $computerInfo.TimeZone
                failedTargetLogonServer                 = $computerInfo.LogonServer
            }

            Write-Output "[$($currTime)] | [$process] | [$procProcess] Failed. Details Below:"
            Write-Output $errorLog
        }

    #Function Ends
    $procEndTime = Get-Date
    $procNetTime = $procEndTime - $procStartTime
    $currTime = Get-Date -format "HH:mm"
    Write-Output "[$($currTime)] | [$process] | [$procProcess] Completed in: $($procNetTime.hours) hours, $($procNetTime.minutes) minutes, $($procNetTime.seconds) seconds"

    }
    if (($InTune) -or ($OfficeApps)){
    #Function Starts, to create a scheduled task that runs once in the user context
    #Log Timing For Individual Functions and their standard function
    $procStartTime = Get-Date 
    $currTime = Get-Date -format "HH:mm"
    $procProcess = "User Enrollment Data Cleanup - Task Build"
    Write-Output "[$($currTime)] | [$process] | [$procProcess] Starting"

    #Standard Try Catch Block
    Try{
        if([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544'){
    #We create a Scheduled Task that is set to run after 1 minute here, to run in the local user context and clear out things that are under their profile
        $script = {
        $procStartTime = Get-Date 
        $currTime = Get-Date -format "HH:mm"
        $procProcess = "User Enrollment Data Cleanup - Run as User"
        Write-Output "[$($currTime)] | [$process] | [$procProcess] Starting"
        $shareLoc = "$env:Temp"
        $dateTime = Get-Date -Format yyyy.MM.dd.HH.mm
        $userTaskExportPath = $shareLoc+$dateTime+"."+$logFileName
        Start-Transcript -Path $userTaskExportPath
        $logFileName = "$($procProcess).txt"
        $chromeBookmarks = "$env:LocalAppData\Google\Chrome\User Data\Default\Bookmarks"
        $edgeBookmarks =  "$env:LocalAppData\Microsoft\Edge\User Data\Default\Bookmarks"
        if(!(Test-Path "C:\_Backup_AppData")){New-Item -Type Directory -Path "C:\_Backup_AppData\"}
        If (Test-Path $edgeBookmarks){Get-Item $edgeBookMarks | Copy-Item -Destination "C:\_Backup_AppData\$($($env:UserName).replace('.','-'))_edgeBookmarks" -Verbose -Force}
        if(Test-Path $chromeBookmarks){Get-Item $chromeBookmarks | Copy-Item -Destination "C:\_Backup_AppData\$($($env:UserName).replace('.','-'))_chromeBookMarks" -Verbose -Force}
        
        If (Get-Process -Name "OneDrive"){Stop-Process -Name "OneDrive" -Force}
        If (Get-Process -name  "Outlook"){Stop-Process -Name "Outlook" -Force}
        If (Get-Process -name "msteams"){Stop-Process -Name "MSTeams" -Force}
        
            
            #These are the functions that removes old user enrollment packages and old user accounts.
            $oldUserEnrollmentPackages = Get-Item -Path "$env:LocalAppData\Packages\Microsoft.AAD.BrokerPlugin*" -ErrorAction Ignore
            $currTime = Get-Date -format "HH:mm"
            Write-Output "[$($currTime)] | [$process] | [$procProcess] Removing Old User AAD Packages"

            while ($oldUserEnrollmentPackages)
            {
            $currTime = Get-Date -format "HH:mm"
            Write-Output "[$($currTime)] | [$process] | [$procProcess] Waiting for AAD Package Availability"
                ForEach ($oldUserEnrollmentPackage in $oldUserEnrollmentPackages)
                {
                    try{
                    Remove-Item -path $oldUserEnrollmentPackage -Force -Recurse -ErrorAction Stop
                    }
                    catch{
                        Start-Sleep -Seconds 5
                        Remove-Item -path $oldUserEnrollmentPackage -Force -Recurse -ErrorAction SilentlyContinue
                    }

                }
                $oldUserEnrollmentPackages = Get-Item -Path "$env:LocalAppData\Packages\Microsoft.AAD.BrokerPlugin*" -ErrorAction Ignore
            }
        If(Get-Item "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"){Get-Item "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"  | Remove-Item -Force -Recurse}
        If (Get-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing" -erroraction Ignore){Get-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing" | Remove-Item -Force -Recurse}
        If (Get-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Identity" -erroraction Ignore){Get-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Identity" | Remove-Item -Force -Recurse}
        if (Get-Item  -Path "$env:LocalAppData\Microsoft\Office\Licenses" -errorAction Ignore){Get-Item  -Path "$env:LocalAppData\Microsoft\Office\Licenses" | Remove-Item -Force -Recurse}
        #Function Ends
        $procEndTime = Get-Date
        $procNetTime = $procEndTime - $procStartTime
        $currTime = Get-Date -format "HH:mm"
        Write-Output "[$($currTime)] | [$process] | [$procProcess] Completed in: $($procNetTime.hours) hours, $($procNetTime.minutes) minutes, $($procNetTime.seconds) seconds"
        }
        New-Item -path "C:\Temp\" -Name "Backup_User_Data.ps1" -value $script -Force

        # Define the action (what the task will do)
        $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-WindowStyle Minimized  -File C:\Temp\Backup_User_Data.ps1 -executionPolicy Bypass"
        # Define the trigger (when the task will run)
        $Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(10)

        # Define the task settings (run only when the user is logged on)
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd

        # Define the principal (current logged-on user context)
        $Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive

        $schedTaskName = "Backup_User_Data_Remove_User_Registrations"
        If (Get-Scheduledtask -TaskName $schedTaskName -ErrorAction SilentlyContinue){
            Unregister-ScheduledTask -TaskName $schedTaskName -Confirm:$False
        }
        
        # Register the task in the Task Scheduler
        Register-ScheduledTask -TaskName $schedTaskName  -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force
        While (!(Get-ScheduledTask -TaskName $schedTaskName -ErrorAction Ignore)){
            $currTime = Get-Date -format "HH:mm"
            Write-Output "[$($currTime)] | [$process] | [$procProcess] Waiting 1 minute for Scheduled Task to be Created and Available"
        }
        Start-ScheduledTask -TaskName $schedTaskName -Verbose | Out-Host

        $taskRunning = $false 
        while (!($taskRunning))
        {
            $currTime = Get-Date -format "HH:mm"
            $schedTaskInfo = Get-ScheduledTaskInfo -TaskName $schedTaskName | Select-Object -Property NextRunTime
            $now = Get-Date
            While($schedTaskInfo.NextRunTime -gt $now){
            $now = Get-Date -format "HH:mm"
            $schedTaskInfo = Get-ScheduledTaskInfo -TaskName $schedTaskName | Select-Object -Property NextRunTime
            Write-Output "[$($currTime)] | [$process] | [$procProcess] Waiting for Scheduled Task to Run"
            }
            $taskRunning = $true
        }
        $taskFinished = $false
            while(!($taskFinished)){
            $scheduledTaskResult = Get-ScheduledTask -TaskName "Backup_User_Data_Remove_User_Registrations"
            If ($scheduledTaskResult.state -eq "Running"){
                Write-Output "[$($currTime)] | [$process] | [$procProcess] Waiting for Completion"
                Start-Sleep -Seconds 5
            }
            Else{
                Write-Output "[$($currTime)] | [$process] | [$procProcess] Completed"
                $taskFinished = $true
            }
        }
        }
        else{$procStartTime = Get-Date 
            $currTime = Get-Date -format "HH:mm"
            $procProcess = "User Enrollment Data Cleanup - Run as User"
            Write-Output "[$($currTime)] | [$process] | [$procProcess] Starting"
            $shareLoc = "$env:Temp"
            $dateTime = Get-Date -Format yyyy.MM.dd.HH.mm
            $userTaskExportPath = $shareLoc+$dateTime+"."+$logFileName
            Start-Transcript -Path $userTaskExportPath
            $logFileName = "$($procProcess).txt"
            $chromeBookmarks = "$env:LocalAppData\Google\Chrome\User Data\Default\Bookmarks"
            $edgeBookmarks =  "$env:LocalAppData\Microsoft\Edge\User Data\Default\Bookmarks"
            if(!(Test-Path "C:\_Backup_AppData")){New-Item -Type Directory -Path "C:\_Backup_AppData\"}
            If (Test-Path $edgeBookmarks){Get-Item $edgeBookMarks | Copy-Item -Destination "C:\_Backup_AppData\$($($env:UserName).replace('.','-'))_edgeBookmarks" -Verbose -Force}
            if(Test-Path $chromeBookmarks){Get-Item $chromeBookmarks | Copy-Item -Destination "C:\_Backup_AppData\$($($env:UserName).replace('.','-'))_chromeBookMarks" -Verbose -Force}
            
            If (Get-Process -Name "OneDrive"){Stop-Process -Name "OneDrive" -Force}
            If (Get-Process -name  "Outlook"){Stop-Process -Name "Outlook" -Force}
            If (Get-Process -name "msteams"){Stop-Process -Name "MSTeams" -Force}
            
                
                #These are the functions that removes old user enrollment packages and old user accounts.
                $oldUserEnrollmentPackages = Get-Item -Path "$env:LocalAppData\Packages\Microsoft.AAD.BrokerPlugin*" -ErrorAction Ignore
                $currTime = Get-Date -format "HH:mm"
                Write-Output "[$($currTime)] | [$process] | [$procProcess] Removing Old User AAD Packages"
    
                while ($oldUserEnrollmentPackages)
                {
                $currTime = Get-Date -format "HH:mm"
                Write-Output "[$($currTime)] | [$process] | [$procProcess] Waiting for AAD Package Availability"
                    ForEach ($oldUserEnrollmentPackage in $oldUserEnrollmentPackages)
                    {
                        try{
                        Remove-Item -path $oldUserEnrollmentPackage -Force -Recurse -ErrorAction Stop
                        }
                        catch{
                            Start-Sleep -Seconds 5
                            Remove-Item -path $oldUserEnrollmentPackage -Force -Recurse -ErrorAction SilentlyContinue
                        }
    
                    }
                    $oldUserEnrollmentPackages = Get-Item -Path "$env:LocalAppData\Packages\Microsoft.AAD.BrokerPlugin*" -ErrorAction Ignore
                }
            If(Get-Item "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"){Get-Item "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"  | Remove-Item -Force -Recurse}
            If (Get-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing" -erroraction Ignore){Get-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Licensing" | Remove-Item -Force -Recurse}
            If (Get-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Identity" -erroraction Ignore){Get-Item -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Identity" | Remove-Item -Force -Recurse}
            if (Get-Item  -Path "$env:LocalAppData\Microsoft\Office\Licenses" -errorAction Ignore){Get-Item  -Path "$env:LocalAppData\Microsoft\Office\Licenses" | Remove-Item -Force -Recurse}
            #Function Ends
            $procEndTime = Get-Date
            $procNetTime = $procEndTime - $procStartTime
            $currTime = Get-Date -format "HH:mm"
            Write-Output "[$($currTime)] | [$process] | [$procProcess] Completed in: $($procNetTime.hours) hours, $($procNetTime.minutes) minutes, $($procNetTime.seconds) seconds"
    }
    }
    
    
    Catch
    {
        $errorDetails = $error[0] | Select-Object *
        $currTime = Get-Date -format "HH:mm"
        $errorLog += [PSCustomObject]@{
            processFailed                           = $procProcess
            timeToFail                              = $currTime
            reasonFailed                            = $errorDetails 
            failedTargetStandardName                = $computerinfo.CsName
            failedTargetSerialNumber                = $computerInfo.BiosSerialNumber
            failedTargetDNSName                     = $computerinfo.CsDNSHostName
            failedTargetUser                        = $computerInfo.CsUserName
            failedTargetWorkGroup                   = $computerInfo.CsWorkgroup
            failedTargetDomain                      = $computerInfo.CsDomain
            failedTargetOSOrganization              = $computerInfo.OsOrganization
            failedTargetChassis                     = $computerInfo.CsChassisSKUNumber
            failedTargetManufacturer                = $computerInfo.CsManufacturer
            failedTargetModel                       = $computerInfo.CsModel
            failedTargetTotalPhysicalMemory         = $computerInfo.CsTotalPhysicalMemory
            failedTargetPhysicallyInstalledMemory   = $computerInfo.PhysicallyInstalledMemory
            failedTargetOsFreePhysicalMemory        = $computerInfo.OsFreePhysicalMemory
            failedTargetOsFreeVirtualMemory         = $computerInfo.OsFreeVirtualMemory
            failedTargetOsInUseVirtualMemory        = $computerInfo.OsInUseVirtualMemory
            failedTargetProcessorName               = $computerInfo.CSProcessors.Name
            failedTargetProcessorSpeedMhz           = $computerInfo.CSProcessors.MaxClockSpeed
            failedTargetProcessorNumOfCores         = $computerInfo.CSProcessors.NumberofCores
            failedTargetProcessorNumOfThreads       = $computerInfo.CSProcessors.NumberOfLogicalProcessors
            failedTargetProcessorStatus             = $computerInfo.CSPRocessors.Status
            failedTargetPowerSupplyState            = $computerInfo.CSPowerSupplyState
            failedTargetThermalState                = $computerInfo.CSThermalState
            failedTargetBootState                   = $computerInfo.CsBootupState
            failedTargetOSVersion                   = $computerInfo.OSVersion
            failedTargetOSStatus                    = $computerInfo.OsStatus
            failedTargetUptime                      = $computerInfo.OsUptime
            failedTargetNumUsers                    = $computerInfo.OsNumberOfUsers
            failedTargetTimezone                    = $computerInfo.TimeZone
            failedTargetLogonServer                 = $computerInfo.LogonServer
        }

        Write-Output "[$($currTime)] | [$process] | [$procProcess] Failed. Details Below:"
        Write-Output $errorLog
    }
    


    #Function Ends
    $procEndTime = Get-Date
    $procNetTime = $procEndTime - $procStartTime
    $currTime = Get-Date -format "HH:mm"
    Write-Output "[$($currTime)] | [$process] | [$procProcess] Completed in: $($procNetTime.hours) hours, $($procNetTime.minutes) minutes, $($procNetTime.seconds) seconds"
    }
    ######################################################### FUNCTIONS END HERE ########################################################
    

    ######################################################### NON TERMINATING ERROR CHECK ###############################################
    $procStartTime = Get-Date 
    $currTime = Get-Date -format "HH:mm"
    $procProcess = "Error Review"
    Write-Output "[$($currTime)] | [$process] | [$procProcess] | Starting"
    if ($null -eq $errorDetails)
    {
        if ($error.count -gt 0)
        {
            ForEach ($event in $error)
            {
                $errorDetails = $event| Select-Object *
                $errorLog += [PSCustomObject]@{
                    processFailed                           = $procProcess
                    timeToFail                              = $currTime
                    reasonFailed                            = $errorDetails 
                    failedTargetStandardName                = $computerinfo.CsName
                    failedTargetDNSName                     = $computerinfo.CsDNSHostName
                    failedTargetUser                        = $computerInfo.CsUserName
                    failedTargetWorkGroup                   = $computerInfo.CsWorkgroup
                    failedTargetDomain                      = $computerInfo.CsDomain
                    failedTargetOSOrganization              = $computerInfo.OsOrganization
                    failedTargetChassis                     = $computerInfo.CsChassisSKUNumber
                    failedTargetManufacturer                = $computerInfo.CsManufacturer
                    failedTargetModel                       = $computerInfo.CsModel
                    failedTargetTotalPhysicalMemory         = $computerInfo.CsTotalPhysicalMemory
                    failedTargetPhysicallyInstalledMemory   = $computerInfo.PhysicallyInstalledMemory
                    failedTargetOsFreePhysicalMemory        = $computerInfo.OsFreePhysicalMemory
                    failedTargetOsFreeVirtualMemory         = $computerInfo.OsFreeVirtualMemory
                    failedTargetOsInUseVirtualMemory        = $computerInfo.OsInUseVirtualMemory
                    failedTargetProcessorName               = $computerInfo.CSProcessors.Name
                    failedTargetProcessorSpeedMhz           = $computerInfo.CSProcessors.MaxClockSpeed
                    failedTargetProcessorNumOfCores         = $computerInfo.CSProcessors.NumberofCores
                    failedTargetProcessorNumOfThreads       = $computerInfo.CSProcessors.NumberOfLogicalProcessors
                    failedTargetProcessorStatus             = $computerInfo.CSPRocessors.Status
                    failedTargetPowerSupplyState            = $computerInfo.CSPowerSupplyState
                    failedTargetThermalState                = $computerInfo.CSThermalState
                    failedTargetBootState                   = $computerInfo.CsBootupState
                    failedTargetOSVersion                   = $computerInfo.OSVersion
                    failedTargetOSStatus                    = $computerInfo.OsStatus
                    failedTargetUptime                      = $computerInfo.OsUptime
                    failedTargetNumUsers                    = $computerInfo.OsNumberOfUsers
                    failedTargetTimezone                    = $computerInfo.TimeZone
                    failedTargetLogonServer                 = $computerInfo.LogonServer
                
                }
            }
            $currTime = Get-Date -format "HH:mm"
            Write-Output "[$($currTime)] | [$process] | [$procProcess] Non-Terminating Error Details Below:`n"
            Write-Output $errorLog
            $errorLog | Export-CSV -Path $errorExportPath
        }
        else
        {
            $currTime = Get-Date -format "HH:mm"
            Write-Output "[$($currTime)] | [$process] | [$procProcess] There were No Errors!`n"
        }
    }
    #If there are non-terminating errors, but they were caught
    Else{
        $currTime = Get-Date -format "HH:mm"
        Write-Output "[$($currTime)] | [$process] | [$procProcess] Error Details Below:`n"
        Write-Output $errorLog
        $errorLog | Export-CSV -Path $errorExportPath

    }
    $procEndTime = Get-Date
    $procNetTime = $procEndTime - $procStartTime
    $currTime = Get-Date -format "HH:mm"
    Write-Output "[$($currTime)] | [$process] | [$procProcess] Completed in: $($procNetTime.hours) hours, $($procNetTime.minutes) minutes, $($procNetTime.seconds) seconds"
    

    ######################################################### FINAL END HERE ########################################################
    $currTime = Get-Date -format "HH:mm"
    $allEndTime = Get-Date 
    $allNetTime = $allEndTime - $allStartTime
    Write-Output "[$($currTime)] | [$process] | Time taken for [$process] Completed in: $($allNetTime.hours) hours, $($allNetTime.minutes) minutes, $($allNetTime.seconds) seconds"
    Stop-Transcript
    $errorExportPath = $shareLoc+$dateTime+"."+$errorLogCSV
    $errorLog | Export-CSV $errorExportPath
    Write-Output "`n`n`nThe Full Error Log is available as a csv at $errorExportPath`n"
    if ($Reboot){
        Write-Output "Restarting at: $(Get-Date)"
        Restart-Computer -Force
    }
    If ($Message){
        New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE -erroraction silentlycontinue | out-null
        $ProtocolHandler = get-item 'HKLM:\SOFTWARE\CLASSES\ToastReboot' -erroraction 'silentlycontinue'
        if (!$ProtocolHandler) {
            New-Item 'HKLM:\SOFTWARE\CLASSES\ToastReboot' -Force
            Set-ItemProperty 'HKLM:\SOFTWARE\CLASSES\ToastReboot' -Name '(DEFAULT)' -Value 'url:ToastReboot' -Force
            Set-ItemProperty 'HKLM:\SOFTWARE\CLASSES\ToastReboot' -Name 'URL Protocol' -Value '' -Force
            New-ItemProperty -Path 'HKLM:\SOFTWARE\CLASSES\ToastReboot' -PropertyType Dword -Name 'EditFlags' -Value 2162688
            New-Item 'HKLM:\SOFTWARE\CLASSES\ToastReboot\Shell\Open\Command' -Force
            Set-ItemProperty 'HKLM:\SOFTWARE\CLASSES\ToastReboot\Shell\Open\Command' -Name '(DEFAULT)' -Value 'pwsh.exe -Command "& {Restart-Computer -Force}" -windowstyle "Hidden"' -Force
        }
        
        
        $gitLogo = New-BTImage -Source 'C:\GIT_Scripts\GIT_Logos\GITLogo.png' -HeroImage
        $header = New-BTText -Content  "Message from GIT"
        $messageContent = New-BTText -Content "GIT has installed updates on your computer at $(get-date). Please click to reboot now."
        $rebootButton = New-BTButton -Content "Reboot now" -Arguments "ToastReboot:" -ActivationType Protocol
        $action = New-BTAction -Buttons $rebootButton
        $Binding = New-BTBinding -Children $header, $messageContent -HeroImage $gitLogo
        $Visual = New-BTVisual -BindingGeneric $Binding
        $Content = New-BTContent -Visual $Visual -Actions $action
        Submit-BTNotification -Content $Content
    }
}
# SIG # Begin signature block
# MIIuqwYJKoZIhvcNAQcCoIIunDCCLpgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBeE2GewYEVLqUu
# TUOSwew0zT/Aj2WmQpJLbesfuACbfKCCFAUwggWQMIIDeKADAgECAhAFmxtXno4h
# MuI5B72nd3VcMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0xMzA4MDExMjAwMDBaFw0z
# ODAxMTUxMjAwMDBaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# AL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/z
# G6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZ
# anMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7s
# Wxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL
# 2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfb
# BHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3
# JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3c
# AORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqx
# YxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0
# viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aL
# T8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjQjBAMA8GA1Ud
# EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBTs1+OC0nFdZEzf
# Lmc/57qYrhwPTzANBgkqhkiG9w0BAQwFAAOCAgEAu2HZfalsvhfEkRvDoaIAjeNk
# aA9Wz3eucPn9mkqZucl4XAwMX+TmFClWCzZJXURj4K2clhhmGyMNPXnpbWvWVPjS
# PMFDQK4dUPVS/JA7u5iZaWvHwaeoaKQn3J35J64whbn2Z006Po9ZOSJTROvIXQPK
# 7VB6fWIhCoDIc2bRoAVgX+iltKevqPdtNZx8WorWojiZ83iL9E3SIAveBO6Mm0eB
# cg3AFDLvMFkuruBx8lbkapdvklBtlo1oepqyNhR6BvIkuQkRUNcIsbiJeoQjYUIp
# 5aPNoiBB19GcZNnqJqGLFNdMGbJQQXE9P01wI4YMStyB0swylIQNCAmXHE/A7msg
# dDDS4Dk0EIUhFQEI6FUy3nFJ2SgXUE3mvk3RdazQyvtBuEOlqtPDBURPLDab4vri
# RbgjU2wGb2dVf0a1TD9uKFp5JtKkqGKX0h7i7UqLvBv9R0oN32dmfrJbQdA75PQ7
# 9ARj6e/CVABRoIoqyc54zNXqhwQYs86vSYiv85KZtrPmYQ/ShQDnUBrkG5WdGaG5
# nLGbsQAe79APT0JsyQq87kP6OnGlyE0mpTX9iV28hWIdMtKgK1TtmlfB2/oQzxm3
# i0objwG2J5VT6LaJbVu8aNQj6ItRolb58KaAoNYes7wPD1N1KarqE3fk3oyBIa0H
# EEcRrYc9B9F1vM/zZn4wggawMIIEmKADAgECAhAIrUCyYNKcTJ9ezam9k67ZMA0G
# CSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5NTla
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDVtC9C
# 0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0JAfhS0/TeEP0F9ce
# 2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJrQ5qZ8sU7H/Lvy0da
# E6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhFLqGfLOEYwhrMxe6T
# SXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+FLEikVoQ11vkunKoA
# FdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh3K3kGKDYwSNHR7Oh
# D26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJwZPt4bRc4G/rJvmM
# 1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQayg9Rc9hUZTO1i4F4z
# 8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbIYViY9XwCFjyDKK05
# huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchApQfDVxW0mdmgRQRNY
# mtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRroOBl8ZhzNeDhFMJlP
# /2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IBWTCCAVUwEgYDVR0T
# AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHwYD
# VR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNV
# HR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEEATAN
# BgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql+Eg08yy25nRm95Ry
# sQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFFUP2cvbaF4HZ+N3HL
# IvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1hmYFW9snjdufE5Btf
# Q/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3RywYFzzDaju4ImhvTnh
# OE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5UbdldAhQfQDN8A+KVssIh
# dXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw8MzK7/0pNVwfiThV
# 9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnPLqR0kq3bPKSchh/j
# wVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatEQOON8BUozu3xGFYH
# Ki8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bnKD+sEq6lLyJsQfmC
# XBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQjiWQ1tygVQK+pKHJ6l
# /aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbqyK+p/pQd52MbOoZW
# eE4wgge5MIIFoaADAgECAhAOeHFNrWpQadD+X7fviblJMA0GCSqGSIb3DQEBCwUA
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTEwHhcNMjQxMTEyMDAwMDAwWhcNMjUxMTEyMjM1OTU5WjCBwTET
# MBEGCysGAQQBgjc8AgEDEwJVUzEZMBcGCysGAQQBgjc8AgECEwhNYXJ5bGFuZDEd
# MBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEjAQBgNVBAUTCUQwMDY2ODUz
# MzELMAkGA1UEBhMCVVMxETAPBgNVBAgTCE1hcnlsYW5kMRIwEAYDVQQHEwlUYW5l
# eXRvd24xEzARBgNVBAoTCkV2YXBjbyBJbmMxEzARBgNVBAMTCkV2YXBjbyBJbmMw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC4VmB16u7QUgi83PhnLWjD
# oSTpgThLIDktbX4jcd5iGW2EIcARhLhX7iUEamx07U9bQgFAElu145EAozu/h/Ed
# KmK6ij2NWOeiv7le/1LlElR+5A5zxYETPArZvETgBa0aORcVZ6MZogWcoSCUH9uo
# 64yLR7rCUAFYjLwfWfnMrjFclOhmzHhQdkrhz527pJbOIPjJFNITmM6RhYzTq02L
# 0fPq7oIkL5eXgkFljr90IUDj5mL5aqRgTUzMEfTWBJYeBkA+lS6xaPyPhFtQazxi
# Rel1K+kyD+1ohzgUOWXIO3RiQKCgWeuVJZMQrS1+ODcFba/hepMT8MKDNGwXeSc5
# RHNJ2mCkdbP3CfIO7BhKJC+4p7L6a1+YsRR/c3CEcFH++NsOKdcmFbzpzpH3skNe
# X+71Vn0VNXmgrSje/x26Wo+FKzra50FA57QXtBB3rz/0mtZaLWuqkoG/tSuBjNvV
# J2yCAajIuiS5Nooik8+76Ajw4PQSkIe/s9xOzHc6gvxekQtLYV6fJQ/f15VuPSZ1
# Gdo9310rzQWnB9xiZe2BR1ylzq/5/aM/1HmU+zXwyEFthy2wFkGXJK8u4JC7vmcH
# Rp7pyhhwyWn56UHZANllz08OpeR13yvWQZeaJwp0TOLgHglth+XDuULMv8vkR98c
# ge7YAkIOLVFeiLUKjYGT1wIDAQABo4ICAjCCAf4wHwYDVR0jBBgwFoAUaDfg67Y7
# +F8Rhvv+YXsIiGX0TkIwHQYDVR0OBBYEFOdeboNElsywAuHpL+DqJa6ik83MMD0G
# A1UdIAQ2MDQwMgYFZ4EMAQMwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdp
# Y2VydC5jb20vQ1BTMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcD
# AzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0Ex
# LmNybDBToFGgT4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsG
# AQUFBwEBBIGHMIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wXAYIKwYBBQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0
# MAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggIBAM8Sju/eIoI6/OS+2VcTmBjQ
# CJsjEtyjxGAWS7OQm1XuJqOyR4XZIFbi9UE5A0zDAuH4pwD8fYpEfn3terhffRHz
# /HA/cMSu92C4OJAf/AUO20BMo7fRnWh1F+wTUv+K1bCWHZS245m03NE+UqlvTNu8
# LzvvXBTtEckQdB2XlY39MdWDYxJFINL6bQT7vtGdBvZqDGAeyTaVlvSxHkvDVDtQ
# r2K1y3aaZyz91Ek+eTyeCxb0dUkEsntT066cqd1DuvDg5o6qsCJXS/CEfV5u27py
# 5XV3GMeRSw9iAK8eujrfCoztRUia+ZLZoZ/5isqRmokeynNi+KY/VSe2jMIqoJ3J
# yNsEZFJAPF0M6hDcAjzETOSA1ZcvR6npB1jaUDPWKIld7s8gpWV/8jM+61Kh3Sj0
# I1O2JZCxpLegx1dDSCkmUufK6Io3FH1zjQtddQnlAFwW+3IPfyoP0YKlIyenlF0h
# fuBxOlaJ8LZ7VLFcNWzGjhOdwOV/t+JnxVJPFx1RXR3Q8NmmMe08afq22TLpkXQL
# KwXuKtSi3h1cmOFPtnEqABB5VLUPYZlINCgNFWSY+gKCULWJKkQhpVN5r1yO3LbT
# tDRvoQRwPoNs9CkNVl9HQ+Qv6sbpqAqLfGEeN+SEv7lo9lUsUKxAaw1yaVBHIISI
# anBZbb3T3Kf7DmGQDth6MYIZ/DCCGfgCAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUG
# A1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQg
# RzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAOeHFNrWpQ
# adD+X7fviblJMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKA
# AKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJlm9KfS4UIizTsqskzcgTO6
# Apqnjb82BLM8J3SULwd6MA0GCSqGSIb3DQEBAQUABIICABUBDA6nDgn98dTRJuXb
# N/Ug7UG70wIMGHGil+6N9+jrKcUCLYakWgZpo093oGDe0CE0ceeIfusYv11KEk9e
# wXGMNN7LaoCLKRuPu/qnMSv9oh0Hoka7PCMjqQn6tVPa6whnq/XTWaH6BMp+6CtV
# gu+nuNxwciiuJy4zjW1mg3zFGhgwdWJUryyBODhkbJL0QBZfH4LdFfYnp8lkqDvo
# Y/YWlunjvCEqE0dQbEsgK6L6GIiAcoFI62k7etSIo0dWjtpXHXfe1JIZ/nlBBjfr
# JBsUQq6fdxMzgUuj+nnW6iTMSJTVeOG30dv0mN+h89JChdMDw15JRf51noRv0S15
# Lg8koSkoqBAufwEtCefHNThUF2yroEkS58o3r3ixp9uXAZOHSKiZG20q9upsATDh
# Tz769X81pzMLb11WZwT/7gQ3iHmC3FoMea4NteamMember6NEYtUr5+501xb8fmvZWKIH+J
# yoL+Yi+/C/DTbwJ6ybhh0kb63Q7Jsvcru9p+R7/ShdyUkwt5iUesvFOUAuqfN0tD
# lTLWwRpBFY8qzwzk3okKzHo5ELTA1k8HjN5pKI3yA3PsOfmFrHYr9ryyncVzkqRl
# qZq9OW2GQlqhzTRjBePFpAJz3l6xC2LZQd29m/5oUt2e01dvmFQnmC5w49OE13dV
# cMDErA7VzKZmlCsIw7SxSslKoYIWyTCCFsUGCisGAQQBgjcDAwExgha1MIIWsQYJ
# KoZIhvcNAQcCoIIWojCCFp4CAQMxDTALBglghkgBZQMEAgEwgeUGCyqGSIb3DQEJ
# EAEEoIHVBIHSMIHPAgEBBgkrBgEEAaAyAgMwMTANBglghkgBZQMEAgEFAAQgOVPP
# 7jW/RzKx4UrJxaSncjAqC5lsbG90K9eeWSlpQYACFE93QE38jAtfifA6SzTf/sqQ
# syCVGA8yMDI1MDEyNzE2MTAzMVowAwIBAaBgpF4wXDELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoMEEdsb2JhbFNpZ24gbnYtc2ExMjAwBgNVBAMMKUdsb2JhbHNpZ24gVFNB
# IGZvciBBZHZhbmNlZCAtIEc0IC0gMjAyMzExoIISUzCCBmswggRToAMCAQICEAEZ
# dXRxyZLXRN+lluu5cBUwDQYJKoZIhvcNAQELBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjMxMTAyMTAzMDAyWhcNMzQx
# MjA0MTAzMDAyWjBcMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEyMDAGA1UEAwwpR2xvYmFsc2lnbiBUU0EgZm9yIEFkdmFuY2VkIC0gRzQg
# LSAyMDIzMTEwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCyNUZ0qoON
# 1ZanPEjVxcqo31S+CKuh31zpSdBgXrWlGvdDWEOXPPRnYwgyPBl/K9lVRtXUjMBc
# z6TFpRq6pyvOJkIhPOW7oaOV3WDqElWu787cMoTto7XgP3PRNbibu8VE3eG46/NZ
# rYn2cY9aCvoKkgWEDZcBvwW7/FgBs43J1AWFp5ArbqzT2U7apyQ1lm+qs6BBO+D5
# 5xGO1WYCgC09zM8epJaLF4DcTDkaJHUsxXcW2ZGDJn/nE4uiRVTmtkp359ItLuew
# PEjZxo37evQrvKYiSKLX3q14R4gMX5v0kUoGHPoDnmpWHisw4/OOWbC0Hx5hOIZ5
# +YODlI8JMEIztA63iIIYLT/XgYsnoGnx0wWuxkWjwh+brenAyE/X58anQTJo/1nK
# VFz7v9kfFvBS0s+4NZWlkc6jHfV2UpjskWGLCaGtmZnorJQolziMCa48nPh+UaI3
# ashxuh1PDSYBVn5Xw3VC2FPgY2Pdfp4dqGLozv6ZWVP28wCK/ZOVz9ECAwEAAaOC
# AagwggGkMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAd
# BgNVHQ4EFgQUxL7uhzyJdA7es+4ZG4UMzkFOf50wVgYDVR0gBE8wTTAIBgZngQwB
# BAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2Jh
# bHNpZ24uY29tL3JlcG9zaXRvcnkvMAwGA1UdEwEB/wQCMAAwgZAGCCsGAQUFBwEB
# BIGDMIGAMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9j
# YS9nc3RzYWNhc2hhMzg0ZzQwQwYIKwYBBQUHMAKGN2h0dHA6Ly9zZWN1cmUuZ2xv
# YmFsc2lnbi5jb20vY2FjZXJ0L2dzdHNhY2FzaGEzODRnNC5jcnQwHwYDVR0jBBgw
# FoAU6hbGaefjy1dFOTOk8EC+0MO9ZZYwQQYDVR0fBDowODA2oDSgMoYwaHR0cDov
# L2NybC5nbG9iYWxzaWduLmNvbS9jYS9nc3RzYWNhc2hhMzg0ZzQuY3JsMA0GCSqG
# SIb3DQEBCwUAA4ICAQCzMtHqZ//b36e0N0Rd7R6+diPJzgPtTdRq5zOMPF8gYtvu
# 6Ww4OeWZcfsmkR8nsXNcAxnPaDLQ1eZ2eEqqPJcy0hXuehwyPGCnQcq5PvFB6sPT
# 8cflvt4axsGOIt/WgOWP8qyyIY14tsSJjJS9MnO42JdEPNdmbA0cEFxeqIhAvaCu
# TlotZE8GJaWExjhwx1RzFI1XFqkwHKgJSd+lAQYDvxOzdJSbB4GvDUGQVSmwYKlU
# +jggM84Jug5MZ1iBhqntiIapmOO25UaXJEdsSNEQaspxsj5dwz0tIYJrg2Nvl8CR
# /vt9lrmqwBzNpa2QeIDWfW2JKkCOrCX664g2I36G8vu1Bu0ogyyz2pp6b0gRFpQ2
# tUVAnYE1DcWxjJs75jzpehhQ+TmKkne7kSJuoLlbKgFAKOTRSKkwjqKGEjdNyVmZ
# x6YDf+GRCn0K+AtCDnGu9s+65TH4+R8t8OAKjISMpTmjO7DzNtlD1ZuYJA/QwuMm
# Pq3h+/seq94G9vtoQewx36nJHowZ9j72Hpgu0WCBWyZ09FROQATftV7U9+7wDYdv
# QECnaeooyKGpT3cSiTFq6ZqDd4upxUQz7rdpTiy0p7SVeJvWqkAsNhqnREOzUthg
# xnNXv3zWNdMjo2BCItYWFc4TGunO9eXPWr6sP3Pp+nO/Gc2il2bKHGANor1UzDCC
# BlkwggRBoAMCAQICDQHsHJJA3v0uQF18R3QwDQYJKoZIhvcNAQEMBQAwTDEgMB4G
# A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2JhbFNp
# Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMTgwNjIwMDAwMDAwWhcNMzQxMjEw
# MDAwMDAwWjBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1z
# YTExMC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQg
# LSBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAPAC4jAj+uAb4Zp0
# s691g1+pR1LHYTpjfDkjeW10/DHkdBIZlvrOJ2JbrgeKJ+5Xo8Q17bM0x6zDDOuA
# Zm3RKErBLLu5cPJyroz3mVpddq6/RKh8QSSOj7rFT/82QaunLf14TkOI/pMZF9nu
# Mc+8ijtuasSI8O6X9tzzGKBLmRwOh6cm4YjJoOWZ4p70nEw/XVvstu/SZc9FC1Q9
# sVRTB4uZbrhUmYqoMZI78np9/A5Y34Fq4bBsHmWCKtQhx5T+QpY78Quxf39GmA6H
# PXpl69FWqS69+1g9tYX6U5lNW3TtckuiDYI3GQzQq+pawe8P1Zm5P/RPNfGcD9M3
# E1LZJTTtlu/4Z+oIvo9Jev+QsdT3KRXX+Q1d1odDHnTEcCi0gHu9Kpu7hOEOrG8N
# ubX2bVb+ih0JPiQOZybH/LINoJSwspTMe+Zn/qZYstTYQRLBVf1ukcW7sUwIS57U
# QgZvGxjVNupkrs799QXm4mbQDgUhrLERBiMZ5PsFNETqCK6dSWcRi4LlrVqGp2b9
# MwMB3pkl+XFu6ZxdAkxgPM8CjwH9cu6S8acS3kISTeypJuV3AqwOVwwJ0WGeJoj8
# yLJN22TwRZ+6wT9Uo9h2ApVsao3KIlz2DATjKfpLsBzTN3SE2R1mqzRzjx59fF6W
# 1j0ZsJfqjFCRba9Xhn4QNx1rGhTfAgMBAAGjggEpMIIBJTAOBgNVHQ8BAf8EBAMC
# AYYwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU6hbGaefjy1dFOTOk8EC+
# 0MO9ZZYwHwYDVR0jBBgwFoAUrmwFo5MT4qLn4tcc1sfwf8hnU6AwPgYIKwYBBQUH
# AQEEMjAwMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20v
# cm9vdHI2MDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5j
# b20vcm9vdC1yNi5jcmwwRwYDVR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEW
# Jmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3
# DQEBDAUAA4ICAQB/4ojZV2crQl+BpwkLusS7KBhW1ky/2xsHcMb7CwmtADpgMx85
# xhZrGUBJJQge5Jv31qQNjx6W8oaiF95Bv0/hvKvN7sAjjMaF/ksVJPkYROwfwqSs
# 0LLP7MJWZR29f/begsi3n2HTtUZImJcCZ3oWlUrbYsbQswLMNEhFVd3s6UqfXhTt
# chBxdnDSD5bz6jdXlJEYr9yNmTgZWMKpoX6ibhUm6rT5fyrn50hkaS/SmqFy9vck
# S3RafXKGNbMCVx+LnPy7rEze+t5TTIP9ErG2SVVPdZ2sb0rILmq5yojDEjBOsghz
# n16h1pnO6X1LlizMFmsYzeRZN4YJLOJF1rLNboJ1pdqNHrdbL4guPX3x8pEwBZzO
# e3ygxayvUQbwEccdMMVRVmDofJU9IuPVCiRTJ5eA+kiJJyx54jzlmx7jqoSCiT7A
# SvUh/mIQ7R0w/PbM6kgnfIt1Qn9ry/Ola5UfBFg0ContglDk0Xuoyea+SKorVdmN
# tyUgDhtRoNRjqoPqbHJhSsn6Q8TGV8Wdtjywi7C5HDHvve8U2BRAbCAdwi3oC8aN
# bYy2ce1SIf4+9p+fORqurNIveiCx9KyqHeItFJ36lmodxjzK89kcv1NNpEdZfJXE
# Q0H5JeIsEH6B+Q2Up33ytQn12GByQFCVINRDRL76oJXnIFm2eMakaqoimzCCBYMw
# ggNroAMCAQICDkXmuwODM8OFZUjm/0VRMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE0MTIxMDAwMDAwMFoXDTM0MTIxMDAw
# MDAwMFowTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNV
# BAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wggIiMA0GCSqGSIb3
# DQEBAQUAA4ICDwAwggIKAoICAQCVB+hzymb57BTKezz3DQjxtEULLIK0SMbrWzyu
# g7hBkjMUpG9/6SrMxrCIa8W2idHGsv8UzlEUIexK3RtaxtaH7k06FQbtZGYLkoDK
# RN5zlE7zp4l/T3hjCMgSUG1CZi9NuXkoTVIaihqAtxmBDn7EirxkTCEcQ2jXPTyK
# xbJm1ZCatzEGxb7ibTIGph75ueuqo7i/voJjUNDwGInf5A959eqiHyrScC5757yT
# u21T4kh8jBAHOP9msndhfuDqjDyqtKT285VKEgdt/Yyyic/QoGF3yFh0sNQjOvdd
# Osqi250J3l1ELZDxgc1Xkvp+vFAEYzTfa5MYvms2sjnkrCQ2t/DvthwTV5O23rL4
# 4oW3c6K4NapF8uCdNqFvVIrxclZuLojFUUJEFZTuo8U4lptOTloLR/MGNkl3MLxx
# N+Wm7CEIdfzmYRY/d9XZkZeECmzUAk10wBTt/Tn7g/JeFKEEsAvp/u6P4W4Lsgiz
# YWYJarEGOmWWWcDwNf3J2iiNGhGHcIEKqJp1HZ46hgUAntuA1iX53AWeJ1lMdjlb
# 6vmlodiDD9H/3zAR+YXPM0j1ym1kFCx6WE/TSwhJxZVkGmMOeT31s4zKWK2cQkV5
# bg6HGVxUsWW2v4yb3BPpDW+4LtxnbsmLEbWEFIoAGXCDeZGXkdQaJ783HjIH2BRj
# PChMrwIDAQABo2MwYTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQUrmwFo5MT4qLn4tcc1sfwf8hnU6AwHwYDVR0jBBgwFoAUrmwFo5MT
# 4qLn4tcc1sfwf8hnU6AwDQYJKoZIhvcNAQEMBQADggIBAIMl7ejR/ZVSzZ7ABKCR
# aeZc0ITe3K2iT+hHeNZlmKlbqDyHfAKK0W63FnPmX8BUmNV0vsHN4hGRrSMYPd3h
# ckSWtJVewHuOmXgWQxNWV7Oiszu1d9xAcqyj65s1PrEIIaHnxEM3eTK+teecLEy8
# QymZjjDTrCHg4x362AczdlQAIiq5TSAucGja5VP8g1zTnfL/RAxEZvLS471GABpt
# ArolXY2hMVHdVEYcTduZlu8aHARcphXveOB5/l3bPqpMVf2aFalv4ab733Aw6cPu
# QkbtwpMFifp9Y3s/0HGBfADomK4OeDTDJfuvCp8ga907E48SjOJBGkh6c6B3ace2
# XH+CyB7+WBsoK6hsrV5twAXSe7frgP4lN/4Cm2isQl3D7vXM3PBQddI2aZzmewTf
# bgZptt4KCUhZh+t7FGB6ZKppQ++Rx0zsGN1s71MtjJnhXvJyPs9UyL1n7KQPTEX/
# 07kwIwdMjxC/hpbZmVq0mVccpMy7FYlTuiwFD+TEnhmxGDTVTJ267fcfrySVBHio
# A7vugeXaX3yLSqGQdCWnsz5LyCxWvcfI7zjiXJLwefechLp0LWEBIH5+0fJPB1lf
# iy1DUutGDJTh9WZHeXfVVFsfrSQ3y0VaTqBESMjYsJnFFYQJ9tZJScBluOYacW6g
# qPGC6EU+bNYC1wpngwVayaQQMYIDSTCCA0UCAQEwbzBbMQswCQYDVQQGEwJCRTEZ
# MBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2lnbiBU
# aW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBHNAIQARl1dHHJktdE36WW67lwFTAL
# BglghkgBZQMEAgGgggEtMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDArBgkq
# hkiG9w0BCTQxHjAcMAsGCWCGSAFlAwQCAaENBgkqhkiG9w0BAQsFADAvBgkqhkiG
# 9w0BCQQxIgQg6ISpuap+0WT0p7zfmSvYuYKz2FNa8pg236J6BepFl78wgbAGCyqG
# SIb3DQEJEAIvMYGgMIGdMIGaMIGXBCALeaI5rkIQje9Ws1QFv4/NjlmnS4Tu4t7D
# 2XHB6hc07DBzMF+kXTBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2ln
# biBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBT
# SEEzODQgLSBHNAIQARl1dHHJktdE36WW67lwFTANBgkqhkiG9w0BAQsFAASCAYA3
# 4mfQc5YYsXvdlOfUILKYuPTFSBgfBbh27nMkfUgiPqK2PuGJlhMvzpyooxuC1eLz
# VyQxDT+xNV9KYX0sXxVKgZ44AzKSF+p4GCPXRO5jH3zz6INmULS7zGLWBCQjQW8q
# bcR3ckRewFSNlyjpYzoHsmG4ZZ7sMV6XJ6WmNd+pqlOJuHCWLUi4x+TfIBRMLMAA
# Lv5CPWpyDXl5JQFPBDz46A5z26GU1vdKGrfOZk8idlLy2oFkAs9eOXPnC1UECLvd
# BOEH71tb8Ugx0MsI6En39txJztBoVU2v+KbjNEQrZ5XkD6c7fB0TLFdZXP1AlZFo
# zd+pjvKZhw9uMrxSdQSPSQi9OqcF7pQGfeleBDr9XKy64T2U4gDR6Ej5vtvTAYbb
# jxeiXioXDfqFEjw9HjDdMkAC1pXPIucsS9xo393ZMOLEHOyPlIK04IKOPtkMoiaz
# 4rumMLKhYW4NBvle5GQGiGAqJCSwUM75wzDjFfvxnWa/jnDr+yGEm3b2SpJiTHo=
# SIG # End signature block





