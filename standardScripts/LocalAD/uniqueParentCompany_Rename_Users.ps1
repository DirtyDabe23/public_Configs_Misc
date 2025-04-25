function Rename-uniqueParentCompanyUser {
    $isFinished = $False
    Do{
    cls
    Write-Output "Welcome $($env:USERNAME) to the uniqueParentCompany User Renamer!"
    $exoConnection = Get-ConnectionInformation -erroraction SilentlyContinue
    If (($exoConnection -eq $null) -OR ($exoConnection.State -ne "Connected"))
    {
        Connect-ExchangeOnline -ShowBanner:$false 
    }
    
    
    $userExists = $false
    $usertoModify = $null
    $scopes = $null
    $exoConnection = $null 
    $graphOrLocal = Read-Host -Prompt "Enter 1 to change a Graph User, 2 for Local AD"
    
    If ($graphOrLocal -eq 2)
    {
        do{
            $currentUserName = Read-Host -Prompt "Enter the UPN of the user to fix"
            $userToModify = Get-ADUser -Filter "UserPrincipalName -eq '$currentUserName'" -properties * -erroraction SilentlyContinue
            if ($userToModify -ne $null)
            {
                $userExists = $true
                Write-Output "User Mapped. Proceeding"
            }
            Else
            {
                Write-Output "No user found with Username: $currentUserName Please try again`n`n`n"
            }
        } While ($userExists -eq $false)
    
    
        Write-Output "User Information is as follows:"
        Write-Output "User's UPN: $($usertoModify.UserPrincipalName)"
        Write-Output "User's Aliases: $($usertoModify.proxyAddresses)"
        Write-Output "User's SAM Account Name: $($usertoModify.SamAccountName)"
    
        $firstName = $userToModify.GivenName
        $firstName = $firstName.trim()
        $lastName = $usertoModify.Surname
        $lastName = $lastName.trim()
        $oldSAM = $userToModify.SamAccountName
        $oldUPN = $userToModify.UserPrincipalName
        $currentAliases = $usertomodify.proxyAddresses
        $newAlias = "smtp:"+$oldUPN 
        $upnSuffix ="@" +$usertoModify.userPrincipalName.Split('@')[1]
    
    
                #This is to handle last names with a space or hyphen
                If ($firstName -match " ")
                    {
                        Write-Output "First Name is: $firstName"
                        Write-Output "This has a space"
                        $firstName = $firstName.split(" ")
                        Write-Output "Post Split it is $firstName"
                        $firstName = $firstName[0].substring(0,1).toUpper()+$firstName[0].substring(1).toLower()+" "+$firstName[1].substring(0,1).toUpper()+$firstName[1].substring(1).toLower()
                        Write-Output "Post Edits it is $firstName"
                        $firstName = $firstName.Trim()
                        Write-Output "Post Trim First Name is $firstName"
                        $firstNameUPN = $firstName.Replace(" ","").Trim()
                        Write-Output "First Name for UPN is $firstNameUPN"
                    }
            
            
                ElseIf($firstName -match "-")
                    {
                        Write-Output "This is hyphenated"
                        $firstName = $firstName.split("-")
                        Write-Output "Post Split it is $firstName"
                        $firstName = $firstName[0].substring(0,1).toUpper()+$firstName[0].substring(1).toLower()+"-"+$firstName[1].substring(0,1).toUpper()+$firstName[1].substring(1).toLower()
                        Write-Output "Post Edits it is $firstName"
                        $firstName = $firstName.Trim()
                        Write-Output "Post Trim First Name is $firstName"
                        $firstNameUPN = $firstName.trim()
                        Write-Output "Last Name for UPN is $firstNameUPN"
                    }
                #If their First Name is not Hyphenated or does not contain a space, it does not get modified.
                Else
                {
                $firstNameUPN = $firstName.SubString(0,1) +$FirstName.SubString(1).ToLower()
                }
    
    
                $lastName = $lastName.trim()
                #This is to handle last names with a space or hyphen
                If ($lastName -match " ")
                    {
                        Write-Output "Last Name is: $lastName"
                        Write-Output "This has a space"
                        $lastName = $lastName.split(" ")
                        Write-Output "Post Split it is $lastName"
                        $lastName = $lastName[0].substring(0,1).toUpper()+$lastName[0].substring(1).toLower()+" "+$lastName[1].substring(0,1).toUpper()+$lastName[1].substring(1).toLower()
                        Write-Output "Post Edits it is $lastName"
                        $lastName = $lastName.Trim()
                        Write-Output "Post Trim Last Name is $lastName"
                        $lastNameUPN = $lastName.Replace(" ","").Trim()
                        Write-Output "Last Name for UPN is $lastNameUPN"
                    }
            
            
                ElseIf($lastName -match "-")
                    {
                        Write-Output "This is hyphenated"
                        $lastName = $lastName.split("-")
                        Write-Output "Post Split it is $lastName"
                        $lastName = $lastName[0].substring(0,1).toUpper()+$lastName[0].substring(1).toLower()+"-"+$lastName[1].substring(0,1).toUpper()+$lastName[1].substring(1).toLower()
                        Write-Output "Post Edits it is $lastName"
                        $lastName = $lastName.Trim()
                        Write-Output "Post Trim Last Name is $lastName"
                        $lastNameUPN = $lastName.trim()
                        Write-Output "Last Name for UPN is $lastNameUPN"
                    }
                Else
                {
                $lastNameUPN = $lastName.SubString(0,1) +$lastName.SubString(1).ToLower()
                }
    
                $newUPN = $firstNameUPN + "." +$lastNameUPN + $upnSuffix
    
                $mailNN = $firstnameUPN + "."+$lastNameUPN
                $mailNN = $mailNN.trim()
                If ($mailNN.length -gt 20)
                {
                    $acctSAMName = $mailNN.substring(0,20)
                }
    
                Else
                {
                    $acctSAMName = $mailNN
                }
    
                Write-Output "`n`n`n`nUser Information POST CHANGES WILL BE as follows:"
                Write-Output "User's NEW UPN: $newUPN"
                Write-Output "User's ADDED Aliases: $newAlias"
                Write-Output "User's NEW SAM Account Name: $acctSAMName"
    
                $confirmation = Read-Host "`n`nWould you like to process these changes? Y for Yes, N, for No, E to Edit Manually"
    
                If ($confirmation.substring(0,1) -eq 'Y')
                {
                $primaryAlias = "SMTP:"+$newUPN
                If ($newAlias -in $currentAliases)
                {
                    Write-Output "`n`nAlias is already applied"
                    if ($newAlias -cin $currentAliases)
                    {
                        Write-Output "Already in as Secondary"
                    }
                    Else
                    {
                    Write-Output "Primary Alias needs set to Secondary"
                    set-aduser $usertoModify -remove @{"proxyAddresses"="$($newAlias)"}
                    set-aduser $usertoModify -add @{"proxyAddresses"="$($newAlias)"}
                    Write-Output "Primary Alias now Secondary"
                    }
                       
                }
                Else{
                    Write-Output "Alias does not exist, adding"
                    set-aduser $usertoModify -add @{"proxyAddresses"="$($newAlias)"}
                    Write-Output "Old Primary Alias now Secondary"
                }
                If ($primaryAlias -in $currentAliases)
                {
                    Write-Output "`n`nAlias exists, checking casing applied"
                    if ($primaryAlias -cin $currentAliases)
                    {
                        Write-Output "Already in as Primary"
                    }
                    Else
                    {
                    Write-Output "Primary needs modified to new UPN"
                    set-aduser $usertoModify -remove @{"proxyAddresses"="$($primaryAlias)"}
                    set-aduser $usertoModify -add @{"proxyAddresses"="$($primaryAlias)"}
                    Write-Output "Primary Modified to new UPN"
                    }
                       
                }
                Else{
                    Write-Output "Primary email does not exist as alias, adding"
                    set-aduser $usertoModify -add @{"proxyAddresses"="$($primaryAlias)"}
                    Write-Output "Primary Email Added"
                }
                    Set-ADUser $usertoModify -userprincipalname $newUPN -SamAccountName $acctSAMName -emailAddress $newUPN
                    $userChanged = Get-ADUser $acctSAMNAme -properties * 
                    Write-Output "`n`n`n`nUser Information POST CHANGES are as follows:"
                    Write-Output "User's UPN: $($userChanged.UserPrincipalName)"
                    Write-Output "User's Aliases: $($userChanged.proxyAddresses)"
                    Write-Output "User's SAM Account Name: $($userChanged.SamAccountName)"
    
                    $userDataPath = "\\uniqueParentCompanyusers\users\$oldSAM"
                    $newUserPath = "\\uniqueParentCompanyusers\users\$acctSAMName"
                    If (Test-Path $userDataPath)
                    {
                        Write-Output "Legacy User Drive Detected, renaming"
                        Rename-Item -Path $userDataPath -NewName $newUserPath
                        Write-Output "Verify $($userchanged.displayNAme) can access $newUserPath"
                        
                    }
                    try {
                        Invoke-Command -ComputerName US-TT-VS-AADC01 -ScriptBlock {Start-AdSyncSyncCycle -PolicyType Delta} -erroraction Stop
                    }
                    catch{
                        $busySync = $true
                        while ($busySync)
                        {
                            Write-Output "Waiting 10 seconds for Sync to Finish at $(Get-Date -Format HH:mm:ss)"
                            Start-Sleep -Seconds 10
                            $syncResult = Invoke-Command -ComputerName US-TT-VS-AADC01 -ScriptBlock {Start-AdSyncSyncCycle -PolicyType Delta} -ErrorAction SilentlyContinue
                            if ($syncResult.Result -eq "Success")
                            {
                                $busySYnc = $false
                            } 
                        }
                    }
                    Write-Output "Sync ran at $(Get-Date -Format HH:mm:ss), it will take up to 5 minutes for all changes to replicate"
                }
                If ($confirmation.substring(0,1) -eq 'N')
                {
                    Write-Output "Aborting Changes."
                }
                If ($confirmation.substring(0,1) -eq 'E')
                {
                    $newUPN = Read-Host "Enter the New UPN"
                    $acctSAMNAme = $newUPN.split('@')[0]
                    $primaryAlias = "SMTP:"+$newUPN
                    Set-ADUser $usertoModify -userprincipalname $newUPN -SamAccountName $acctSAMName -emailAddress $newUPN
                                If ($newAlias -in $currentAliases)
                                {
                                    Write-Output "`n`nAlias is already applied"
                                    if ($newAlias -cin $currentAliases)
                                    {
                                        Write-Output "Already in as Secondary"
                                    }
                                    Else
                                    {
                                    Write-Output "Primary Alias needs set to Secondary"
                                    set-aduser $usertoModify -remove @{"proxyAddresses"="$($newAlias)"}
                                    set-aduser $usertoModify -add @{"proxyAddresses"="$($newAlias)"}
                                    Write-Output "Primary Alias now Secondary"
                                    }
                       
                                }
                                Else{
                                    Write-Output "Alias does not exist, adding"
                                    set-aduser $usertoModify -add @{"proxyAddresses"="$($newAlias)"}
                                    Write-Output "Old Primary Alias now Secondary"
                                }
                                If ($primaryAlias -in $currentAliases)
                                {
                                    Write-Output "`n`nAlias exists, checking casing applied"
                                    if ($primaryAlias -cin $currentAliases)
                                    {
                                        Write-Output "Already in as Primary"
                                    }
                                    Else
                                    {
                                    Write-Output "Primary needs modified to new UPN"
                                    set-aduser $usertoModify -remove @{"proxyAddresses"="$($primaryAlias)"}
                                    set-aduser $usertoModify -add @{"proxyAddresses"="$($primaryAlias)"}
                                    Write-Output "Primary Modified to new UPN"
                                    }
                       
                                }
                                Else{
                                    Write-Output "Primary email does not exist as alias, adding"
                                    set-aduser $usertoModify -add @{"proxyAddresses"="$($primaryAlias)"}
                                    Write-Output "Primary Email Added"
                                }
                    $userChanged = Get-ADUser $acctSAMNAme -properties * 
                    Write-Output "`n`n`n`nUser Information POST CHANGES are as follows:"
                    Write-Output "User's UPN: $($userChanged.UserPrincipalName)"
                    Write-Output "User's Aliases: $($userChanged.proxyAddresses)"
                    Write-Output "User's SAM Account Name: $($userChanged.SamAccountName)"
                }
                ElseIf (($confirmation.substring(0,1) -ne 'E') -and ($confirmation.substring(0,1) -ne 'Y') -and ($confirmation.substring(0,1) -ne 'N'))
                {
                    Write-Output "Invalid Selection, Aborting Changes"
                }
    }
    
    If ($graphOrLocal -eq 1)
    {
        $contexts = Get-MGContext 
        If ($contexts -eq $null)
        {
        Connect-MGGRaph -NoWelcome
        }
        $scopes = Get-MGcontext | Select -ExpandProperty Scopes
        If ($scopes -notcontains 'User.ReadWrite.All') 
        {
            Write-Output 'Insufficient privileges. Please PIM, use a different account, or contact GHD'
        }
        Else
        {
            
            $exoConnection = Get-ConnectionInformation
            If (($exoConnection -eq $null) -OR ($exoConnection.State -ne "Connected"))
            {
                Connect-ExchangeOnline -ShowBanner:$false 
            }
    
            
            do{
                $currentUserName = Read-Host -Prompt "Enter the UPN of the user to fix"
                $userToModify = Get-MGBetaUser -userid "$currentUserName" -property * -erroraction SilentlyContinue
                if ($userToModify -ne $null)
                {
                    $userExists = $true
                    Write-Output "User Mapped. Proceeding"
                }
                Else
                {
                    Write-Output "No user found with Username: $currentUserName Please try again`n`n`n"
                }
            } While ($userExists -eq $false)
    
    
            Write-Output "User Information is as follows:"
            Write-Output "User's UPN: $($usertoModify.UserPrincipalName)"
            Write-Output "User's Aliases: $($usertoModify.proxyAddresses)"
    
            $firstName = $userToModify.GivenName
            $firstName = $firstName.trim()
            $lastName = $usertoModify.Surname
            $lastName = $lastName.trim()
            $oldUPN = $userToModify.UserPrincipalName
            $currentAliases = $usertomodify.proxyAddresses
            $newAlias = "smtp:"+$oldUPN 
            $upnSuffix = "@uniqueParentCompany.com"
    
    
                    #This is to handle last names with a space or hyphen
                    If ($firstName -match " ")
                        {
                            Write-Output "First Name is: $firstName"
                            Write-Output "This has a space"
                            $firstName = $firstName.split(" ")
                            Write-Output "Post Split it is $firstName"
                            $firstName = $firstName[0].substring(0,1).toUpper()+$firstName[0].substring(1).toLower()+" "+$firstName[1].substring(0,1).toUpper()+$firstName[1].substring(1).toLower()
                            Write-Output "Post Edits it is $firstName"
                            $firstName = $firstName.Trim()
                            Write-Output "Post Trim First Name is $firstName"
                            $firstNameUPN = $firstName.Replace(" ","").Trim()
                            Write-Output "First Name for UPN is $firstNameUPN"
                        }
                
                
                    ElseIf($firstName -match "-")
                        {
                            Write-Output "This is hyphenated"
                            $firstName = $firstName.split("-")
                            Write-Output "Post Split it is $firstName"
                            $firstName = $firstName[0].substring(0,1).toUpper()+$firstName[0].substring(1).toLower()+"-"+$firstName[1].substring(0,1).toUpper()+$firstName[1].substring(1).toLower()
                            Write-Output "Post Edits it is $firstName"
                            $firstName = $firstName.Trim()
                            Write-Output "Post Trim First Name is $firstName"
                            $firstNameUPN = $firstName.trim()
                            Write-Output "Last Name for UPN is $firstNameUPN"
                        }
                    #If their First Name is not Hyphenated or does not contain a space, it does not get modified.
                    Else
                    {
                    $firstNameUPN = $firstName.SubString(0,1) +$FirstName.SubString(1).ToLower()
                    }
    
    
                    $lastName = $lastName.trim()
                    #This is to handle last names with a space or hyphen
                    If ($lastName -match " ")
                        {
                            Write-Output "Last Name is: $lastName"
                            Write-Output "This has a space"
                            $lastName = $lastName.split(" ")
                            Write-Output "Post Split it is $lastName"
                            $lastName = $lastName[0].substring(0,1).toUpper()+$lastName[0].substring(1).toLower()+" "+$lastName[1].substring(0,1).toUpper()+$lastName[1].substring(1).toLower()
                            Write-Output "Post Edits it is $lastName"
                            $lastName = $lastName.Trim()
                            Write-Output "Post Trim Last Name is $lastName"
                            $lastNameUPN = $lastName.Replace(" ","").Trim()
                            Write-Output "Last Name for UPN is $lastNameUPN"
                        }
                
                
                    ElseIf($lastName -match "-")
                        {
                            Write-Output "This is hyphenated"
                            $lastName = $lastName.split("-")
                            Write-Output "Post Split it is $lastName"
                            $lastName = $lastName[0].substring(0,1).toUpper()+$lastName[0].substring(1).toLower()+"-"+$lastName[1].substring(0,1).toUpper()+$lastName[1].substring(1).toLower()
                            Write-Output "Post Edits it is $lastName"
                            $lastName = $lastName.Trim()
                            Write-Output "Post Trim Last Name is $lastName"
                            $lastNameUPN = $lastName.trim()
                            Write-Output "Last Name for UPN is $lastNameUPN"
                        }
                    Else
                    {
                    $lastNameUPN = $lastName.SubString(0,1) +$lastName.SubString(1).ToLower()
                    }
    
                    $newUPN = $firstNameUPN + "." +$lastNameUPN + $upnSuffix
    
                    $mailNN = $firstnameUPN + "."+$lastNameUPN
                    $mailNN = $mailNN.trim()
                    Write-Output "`n`n`n`nUser Information POST CHANGES WILL BE as follows:"
                    Write-Output "User's NEW UPN: $newUPN"
                    Write-Output "User's ADDED Aliases: $newAlias"
    
                    $confirmation = Read-Host "`n`nWould you like to process these changes? Y for Yes, N, for No, E to Edit Manually"
    
                    If ($confirmation.substring(0,1) -eq 'Y')
                        {
                            $primaryAlias = "SMTP:"+$newUPN
                            If ($newAlias -in $currentAliases)
                            {
                                Write-Output "`n`nAlias is already applied"
                                if ($newAlias -cin $currentAliases)
                                {
                                    Write-Output "Already in as Secondary"
                                }
                                Else
                                {
                                    Write-Output "Primary Alias needs set to Secondary"
                                    Set-Mailbox $usertoModify -emailAddresses @{Remove=$newAlias}
                                    Set-Mailbox $userToModify -emailAddresses @{Add=$newAlias}
                                    Write-Output "Primary Alias now Secondary"
                                }
                                        
                            }
                            Else
                            {
                                Write-Output "Alias does not exist, adding"
                                Set-Mailbox $userToModify -emailAddresses @{Add=$newAlias}
                                Write-Output "Old Primary Alias now Secondary"
                            }
                        If ($primaryAlias -in $currentAliases)
                        {
                            Write-Output "`n`nAlias exists, checking casing applied"
                            if ($primaryAlias -cin $currentAliases)
                            {
                                Write-Output "Already in as Primary"
                            }
                            Else
                            {
                            Write-Output "Primary needs modified to new UPN"
                            Set-Mailbox $usertoModify -emailAddresses @{Remove=$primaryAlias}
                            Set-Mailbox $usertoModify -emailAddresses @{Add=$primaryAlias}
                            Write-Output "Primary Modified to new UPN"
                            }
                                        
                        }
                        Else{
                            Write-Output "Primary email does not exist as alias, adding"
                            Set-Mailbox $usertoModify -emailAddresses @{Add=$primaryAlias}
                            Write-Output "Primary Email Added"
                        }
                        Update-MGBetaUser -UserId $usertoModify -userprincipalname $newUPN 
                        $userChanged = Get-MGBetaUser -UserId $newUPN | select * 
                        Write-Output "`n`n`n`nUser Information POST CHANGES are as follows:"
                        Write-Output "User's UPN: $($userChanged.UserPrincipalName)"
                        Write-Output "User's Aliases: $($userChanged.proxyAddresses)"
                        Write-Output "User's SAM Account Name: $($userChanged.SamAccountName)"
                    }
                    ElseIf ($confirmation.substring(0,1) -eq 'N')
                    {
                        Write-Output "Aborting Changes."
                    }
                    ElseIf ($confirmation.substring(0,1) -eq 'E')
                    {
                        $newUPN = Read-Host "Enter the New UPN"
                        $acctSAMNAme = $newUPN.split('@')[0]
                        $primaryAlias = "SMTP:"+$newUPN
                            If ($newAlias -in $currentAliases)
                            {
                                Write-Output "`n`nAlias is already applied"
                                if ($newAlias -cin $currentAliases)
                                {
                                    Write-Output "Already in as Secondary"
                                }
                                Else
                                {
                                    Write-Output "Primary Alias needs set to Secondary"
                                    Set-Mailbox $usertoModify -emailAddresses @{Remove=$newAlias}
                                    Set-Mailbox $userToModify -emailAddresses @{Add=$newAlias}
                                    Write-Output "Primary Alias now Secondary"
                                }
                                        
                            }
                            Else
                            {
                                Write-Output "Alias does not exist, adding"
                                Set-Mailbox $userToModify -emailAddresses @{Add=$newAlias}
                                Write-Output "Old Primary Alias now Secondary"
                            }
                        If ($primaryAlias -in $currentAliases)
                        {
                            Write-Output "`n`nAlias exists, checking casing applied"
                            if ($primaryAlias -cin $currentAliases)
                            {
                                Write-Output "Already in as Primary"
                            }
                            Else
                            {
                            Write-Output "Primary needs modified to new UPN"
                            Set-Mailbox $usertoModify -emailAddresses @{Remove=$primaryAlias}
                            Set-Mailbox $usertoModify -emailAddresses @{Add=$primaryAlias}
                            Write-Output "Primary Modified to new UPN"
                            }
                                        
                        }
                        Else{
                            Write-Output "Primary email does not exist as alias, adding"
                            Set-Mailbox $usertoModify -emailAddresses @{Add=$primaryAlias}
                            Write-Output "Primary Email Added"
                        }
                        Update-MGBetaUser -userid $usertoModify -userprincipalname $newUPN
                        $userChanged = Get-MGBetaUser -userid $newUPN -properties * 
                        Write-Output "`n`n`n`nUser Information POST CHANGES are as follows:"
                        Write-Output "User's UPN: $($userChanged.UserPrincipalName)"
                        Write-Output "User's Aliases: $($userChanged.proxyAddresses)"
                    }
                    ElseIf (($confirmation.substring(0,1) -ne 'E') -and ($confirmation.substring(0,1) -ne 'Y') -and ($confirmation.substring(0,1) -ne 'N'))
                    {
                        Write-Output "Invalid Selection, Aborting Changes"
                    }
        }
    }
    
    Elseif (($graphOrLocal -ne 1) -and ($graphOrLocal -ne 2))
    {
        Write-Output 'Invalid Selection'
    }
    
                $inputFinished = Read-Host "Would you like to rerun the script? Y for Yes, N, or any other Letter, for No"
    
                If ($inputFinished.substring(0,1) -eq 'Y')
                {
                    $isFinished = $False
                }
                Else
                {
                    $isFinished = $True
                }
    
    }
    while ($isFinished -ne $True)
    }
# SIG # Begin signature block
# MIIuqwYJKoZIhvcNAQcCoIIunDCCLpgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCtrRj306d+jMsT
# zBhGSHXaLfQ2B99+oT9v2H+0NKmA6aCCFAUwggWQMIIDeKADAgECAhAFmxtXno4h
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIsMt2K3NHJig1HZh0hsNSnA
# GXoR5Qg+U0kq5WRSHEUkMA0GCSqGSIb3DQEBAQUABIICAAxQBi44gimxh4YuhkJh
# 434MSOBi2B9EZHe+cOEvgBmdTpYndH5Oay63ijEalg5/+q0oxNi/GAZQtf89cmAq
# p2jY2URk9nLF+HXIM0upmMJr69+SAl5pcBDCtG6ASmFOY9Z15lQQJR3oZl8c+SMN
# PQnS0riwsv/Z1MXQkNT5y7uerK4dXclbrDyhZURzG4fBdxaOAKQfI5ZMp8JJroVK
# DF1AgV4QXE/GzkfA6lWqpgkY7skvWwtfCaAIMEx7ONbmtDMNamqt2XyvImBN2J4v
# sN8uyHgBLgw6Kj5/eQVQbBDY0EHlF+Q6Xo6D4WSYGi8Ho7Z4iM0yaTKx8uUREhN4
# 4yXBGtxf4otX5XxTxXUEhHYJhNht6axgc12CdFJYGX/0TUL27vPorp16S1fZ5tD6
# uokT66agfesmmCZsVmm6YYUKYtd+X9GRBJ1vnxEyyZoMVSfiJ1ZwPBPBfLHUaS5b
# tcwtzM5ez96++p44fGMlhUJTi/QwmjlxaeifC1+apcMBD55/IMshS82klm/5N917
# 88IIJvfGmIL8PYc9vSvvwT/K8QxtXY8v/OUB79iI28lVCheabb5PDCVn/YoAS4X4
# dtEWIIkc/p8ewcOqq6a5Brdn1Thld4/ksu603M/QtIDGXb1ETdf0CHSbqQGobnEB
# OPjxUWpDKBc5S7wRo+l+04LCoYIWyTCCFsUGCisGAQQBgjcDAwExgha1MIIWsQYJ
# KoZIhvcNAQcCoIIWojCCFp4CAQMxDTALBglghkgBZQMEAgEwgeUGCyqGSIb3DQEJ
# EAEEoIHVBIHSMIHPAgEBBgkrBgEEAaAyAgMwMTANBglghkgBZQMEAgEFAAQg2rnV
# 2emZjxRP5rAY+u5szwmw5Xio4CJLozSTzNcU3W4CFHoHBWgw5fzMHIdYcRnTjJTa
# HGO2GA8yMDI0MTIxOTE3NTQ0NFowAwIBAaBgpF4wXDELMAkGA1UEBhMCQkUxGTAX
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
# 9w0BCQQxIgQglpgHaJTDSCDmlcHCnvF8Dhta14AQ3EL+jm2ntGILXa4wgbAGCyqG
# SIb3DQEJEAIvMYGgMIGdMIGaMIGXBCALeaI5rkIQje9Ws1QFv4/NjlmnS4Tu4t7D
# 2XHB6hc07DBzMF+kXTBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2ln
# biBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBT
# SEEzODQgLSBHNAIQARl1dHHJktdE36WW67lwFTANBgkqhkiG9w0BAQsFAASCAYBC
# Y0ke5qQNX1lz+uBO6lJc1riPwGDzr6ily0fhAFhh0LxX+ADPayvXJpY9eW3OAGXH
# EkeLWOItgF4KSbjiaRXhz+AZHIKK0o7RIXsxrUJUADZp3xm88O6UAco6ounzWsjq
# mddqDajqAbCYhUWbK0/a5vYpnTdeCHIPERdccdAhT6K/juVRD5VVqEVDKsYAmv4a
# AB/5dkB/a/qF/pdKa5asPfURnSdMwoyFBJMdDBCTwuGcd7Nn43uY6dZm0IrKPd1V
# IAVRk+3gH6PyD3/rHOCyH422o6YcXdQsA2pDpUWFUrUJECNQG4rA+0waeE8tXr/p
# Neu/XpVmWjsg1KFx11dhcz0+HcVr1xdcU93YN1+OLG2IeYMWf29sU8f6NHn9ls40
# QKVjXb06pB8iB+zaTcOlPInnw7Zn2ZJipXlyt+MInMahgl5nLyHOkQpipHjOJt7h
# ldd8Qin5NJpODt1aAXLHeUGI5uYSWS4dR6DJhly/Jk4F/M+wSsxE6zCprttH8LE=
# SIG # End signature block



