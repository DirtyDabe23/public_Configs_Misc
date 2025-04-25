param(
        [Parameter (Position = 0, HelpMessage = "Enter the Jira Key, Example: GHD-44619")]
        [string]$Key,
        [Parameter (Position = 1, HelpMessage = "Enter the Origin UPN of the user prior to modifications")]
        [string]$originUPN,
        [Parameter(Position = 2 , HelpMessage = "The Ticket Parameters should be passed off here")]
        [PSCustomObject]$paramsFromTicket,
        [Parameter(Position = 3, HelpMessage = "Enter the UPN of the Manager")]
        [String] $newManagerUPN,
        [Parameter (Position = 4, HelpMessage = "If this is a transfer, and will change the UPN Suffix, pass it along here.")]
        [String] $newUPN,
        [Parameter (Position = 5 , HelpMessage = "If this is a transfer, it should be true, otherwise, it should be false")]
        [string] $isTransfer
)
function Set-PrivateErrorJiraRunbook{
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [switch]$Continue
    )
    $currTime = Get-Date -format "HH:mm"
    $errorLog = [PSCustomObject]@{
        timeToFail                      = $currTime
        reasonFailed                    = $error[0] | Select-Object * #gets the most recent error
    }

        
    # Initialize an array to store formatted content
    $jbody = @()

    # Loop through each errorLog item and format it as a JSON paragraph

        $paragraphs = @(
            @{
                type = "paragraph"
                content = @(
                    @{
                        type = "text"
                        text = "Time Failed: $($errorLog.timeToFail)"
                    }
                )
            },
            @{
                type = "paragraph"
                content = @(
                    @{
                        type = "text"
                        text = "Reason Failed: $($errorLog.reasonFailed)"
                    }
                )
            }
        )
        
        $jbody += $paragraphs


    # Create the final JSON payload
    $jsonPayload = @{
        body = @{
            type = "doc"
            version = 1
            content = $jbody
        }
        properties = @(
            @{
                key = "sd.public.comment"
                value = @{
                    internal = $true
                }
            }
        )
    }
    # Convert the PowerShell object to a JSON string
    $jsonPayloadString = $jsonPayload | ConvertTo-Json -Depth 10
    # Perform the API call
    try {
        $response = Invoke-RestMethod -Uri "https://uniqueParentCompany.atlassteamMember.net/rest/api/3/issue/$key/comment" -Method Post -Body $jsonPayloadString -Headers $jiraHeader
        if ($response){
            $currTime = Get-Date -format "HH:mm"
            Write-Output "[$($currTime)] | [$process] | [$procProcess] Internal Comment Successfully Made with Error Details"
        }
    } catch {
        Write-Output "API call failed: $($_.Exception.Message)"
        Write-Output "Payload: $jsonPayload"
    }
    $currTime = Get-Date -format "HH:mm"
    Write-Output "[$($currTime)] | [$process] | [$procProcess] Failed. Details Below:"
    Write-Output $errorLog
    switch ($Continue){
        $False {exit 1}
        Default {$null}
    }
}

function Set-SuccessfulCommentRunbook {
[CmdletBinding()]
param(
[Parameter(ParameterSetName = 'Full', Position = 0)]
[switch]$Continue
)
$jsonPayload = @"
{
"update": {
"comment": [
    {`
            "body": "Resolved via automated process."
        }
    }
]
},
"transition": {
"id": "961"
}
}
"@
    try {
    $response = Invoke-RestMethod -Uri "https://uniqueParentCompany.atlassteamMember.net/rest/api/2/issue/$key/transitions" -Method Post -Body $jsonPayload -Headers $jiraHeader
    if ($response){
    $currTime = Get-Date -format "HH:mm"
    Write-Output "[$($currTime)] | [$process] | [$procProcess] Internal Comment Successfully Made with Error Details"
    }
    } catch {
    Write-Output "API call failed: $($_.Exception.Message)"
    Write-Output "Payload: $jsonPayload"
    }
    $currTime = Get-Date -format "HH:mm"
    Write-Output "[$($currTime)] | [$process] | [$procProcess] Failed. Details Below:"
    Write-Output $errorLog
    switch ($Continue){
    $False {exit 1}
    Default {Continue}
    }
}
function Set-PublicErrorJira{
    [CmdletBinding()]
    param(
    [Parameter(Position = 0)]
    [switch]$Continue
    ) 
    $jsonPayload = @"
    {
    "update": {
        "comment": [
            {
                "add": {
                    "body": "Automation Failed. GIT will review Internal Logs and report back"
                }
            }
        ]
    },
    "transition": {
    "id": "981"
    }
}
"@
        Invoke-RestMethod -Uri "https://uniqueParentCompany.atlassteamMember.net/rest/api/2/issue/$key/transitions" -Method Post -Body $jsonPayload -Headers $jiraHeader
        
    switch ($Continue){
    $False {$null}
    Default {Continue}
    }
}
function Rename-uniqueParentCompanyUser {
    <#
    .SYNOPSIS
    This renames a specified user, either on local AD or Graph.


    .DESCRIPTION
    This function renames an uniqueParentCompany User either on Graph, or their Local AD server.
    It will update their UPN, Mail Nickname, DisplayName, DistinguishedName, CannonicalName, GivenName, SurName, and ProxyAddresses

    .PARAMETER CurrentUserName
    The current UPN of the user to modify

    .EXAMPLE
    #The following will rename a user with the UPN matching TTestUserLast@domain.extension
    #If their domain is different from the account running, you are required to have delegated permissions.
    Rename-uniqueParentCompanyUser -CurrentUserName "TTestUserLast@domain.extension"

    .EXAMPLE
    #The following will update the user to the 'FirstName.LastName' format, without confirmation.
    Rename-uniqueParentCompanyUser -currentUserName "testUser@domain.extension" -Auto
    
    .EXAMPLE
    #The following will rename a testUser@domain.extension and set the following properties
    Rename-uniqueParentCompanyUser -currentUserName "testUser@domain.extension" -Auto -custom -newUPN "TestName.TestLast-NewLast@domain.extension" -firstName "tName" -lastName "lastName"
    #Properties Changed:
    #UPN + Email:                                   TestName.TestLast-NewLast@domain.extension
    #MailNickName , DisplayName, CannonicalName:    Tname Lname 
    #FirstName:                                     Tname
    #LastName:                                      Lastname
    #SamAccountName:                                TestName.TestLast-Ne
    #Classic Logon Format in this case would be:    DOMAIN\TestName.TestLast-Ne
    #oldAlias:                                      smtp:testUser@domain.extension
    #primaryAlias:                                  SMTP:TestName.TestLast-NewLast@domain.extension
    
    .NOTES
    If you are not authenticated with Connect-MgGraph and Connect-ExchangeOnline you will be prompted to do so every time.
    You will need Graph: 'User.ReadWrite.All' permissions
    #>
    [CmdletBinding()]
    param(
    [Parameter(Position = 0, HelpMessage = "Enter the User Principal Name for the user to modify",Mandatory = $true)]
    [ValidatePattern( "[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+(?:\.[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+)*@(?:[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?")]
    [string]$currentUserName,
    [Parameter(Position = 1,HelpMessage = "Enter the path to the user's data directory.`nExample:\\uniqueParentCompanyusers\users\`nEnter")]
    [string]$userDataDirectory ="\\uniqueParentCompanyusers\users\",
    [Parameter(ParameterSetName="Auto",Position =3,HelpMessage = "Use this Switch to Bypass all Confirmations and Process Changes in Bulk")]
    [Parameter(ParameterSetName="Custom",Position =3,HelpMessage = "Use this Switch to Bypass all Confirmations and Process Changes in Bulk")]
    [switch]$auto,
    [Parameter(ParameterSetName="Auto",Position =4,HelpMessage = "Use this Switch to Bypass all Confirmations and Process Changes in Bulk")]
    [Parameter(ParameterSetName="Custom",Position =4,HelpMessage = "Use this switch to be able to pass 'newUPN' 'firstName' and 'lastName' in programmatically for bulk use.")]
    [switch]$custom,
    [Parameter(ParameterSetName="Custom",Position =5,HelpMessage = "Enter the New UPN",Mandatory = $true)]
    [ValidatePattern( "[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+(?:\.[-A-Za-z0-9!#$%&'*+/=?^_`{|}~]+)*@(?:[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[-A-Za-z0-9]*[A-Za-z0-9])?")]
    [string]$newUPN,
    [Parameter(ParameterSetName="Custom",Position =6,HelpMessage = "Enter the User's Preferred Given Name",Mandatory = $true)]
    [string]$firstName,
    [Parameter(ParameterSetName="Custom",Position =7,HelpMessage = "Enter the User's Surname",Mandatory = $true)]
    [string]$lastName
    
    )

    function Format-Name {
        [CmdletBinding()]
        param(
            [Parameter(Position = 0, HelpMessage = "Enter the Input Name to Format", Mandatory = $true)]
            [string]$inputName
        )
        # Trim leading and trailing spaces
        $inputName = $inputName.Trim()
        $inputNameFormatted = $null
    
        # Handle names with spaces
        if ($inputName -match " ") {
            $splitInputName = $inputName.Split(" ") | Where-Object { $_ -ne "" } # Remove empty strings caused by extra spaces
            $runningStringPre = $null
            foreach ($splitName in $splitInputName) {
                # Format each part of the name
                if ($splitName.Length -gt 1) {
                    $formattedString = $splitName.Substring(0, 1).ToUpper() + $splitName.Substring(1).ToLower()
                } else {
                    $formattedString = $splitName.ToUpper() # Handle single-character cases
                }
    
                # Combine formatted strings
                if ($null -ne $runningStringPre) {
                    $runningStringPre = $runningStringPre + " " + $formattedString
                } else {
                    $runningStringPre = $formattedString
                }
            }
            $runningStringPost = $runningStringPre
            return $runningStringPost
        }
        # Handle hyphenated names
        if ($inputName -match "-") {
            $splitInputName = $inputName.Split("-")
            if ($splitInputName.Count -eq 2) {
                $formattedString = $splitInputName[0].Substring(0, 1).ToUpper() + $splitInputName[0].Substring(1).ToLower() + "-" +
                                   $splitInputName[1].Substring(0, 1).ToUpper() + $splitInputName[1].Substring(1).ToLower()
                return $formattedString
            } else {
                Write-Error "Hyphenated name format is invalid."
            }
        }
        # Handle single-part names
        if ($inputName.Length -gt 1) {
            $inputNameFormatted = $inputName.Substring(0, 1).ToUpper() + $inputName.Substring(1).ToLower()
        } else {
            $inputNameFormatted = $inputName.ToUpper() # Handle single-character names
        }
        return $inputNameFormatted
    }
    
    function Add-Alias{
        [CmdletBinding()]
        param(
        [Parameter(Position = 0, HelpMessage = "Enter the Alias to add. `nExample: smtp:exampleEmail@domain.com will set a secondary alias for that email address`n`
        Example: SMTP:exampleEmail@domain.com will the primary email address to said example email`nEnter",Mandatory = $true)]
        [string]$inputAlias,
        [Parameter(Position = 1, HelpMessage = "Enter 'Graph' to modify on Graph, 'Local' to Modify on Local",Mandatory = $true)]
        [string]$graphOrLocal
        )
        $aliasType = $null
        switch ($inputAlias -clike "smtp:*") {
            ($true){$aliasType = "Secondary"}
            Default {$aliasType = "Primary"}
        }
        
        If ($inputAlias -in $currentAliases){
            Write-Output "`n`n$inputAlias is already applied"
            if ($inputAlias -cin $currentAliases){
                Write-Output "$aliasType Alias Already $inputAlias"
            }
            Else{
                Write-Output "$aliasType Alias needs set to $aliasType"
                switch ($graphOrLocal) {
                    "Graph"{
                        $null
                    }
                    "Local"{
                        switch ($runningUserDomainSuffix -eq $upnSuffix){
                            $true{Set-AdUser $usertoModify -remove @{"proxyAddresses"="$($inputAlias)"} -ErrorAction Stop
                            Set-AdUser $usertoModify -add @{"proxyAddresses"="$($inputAlias)"} -ErrorAction Stop}
                            $false{Set-AdUser $usertoModify -remove @{"proxyAddresses"="$($inputAlias)"} -ErrorAction Stop -Server $upnSuffix
                            Set-AdUser $usertoModify -add @{"proxyAddresses"="$($inputAlias)"} -ErrorAction Stop}
                        }
                    }
                }

                Write-Output "$aliasType Alias now $inputAlias"
            }
        }
        Else{
            Write-Output "Alias $inputAlias Type $aliasType does not exist, adding"
            switch ($graphOrLocal){
                'Graph'{ 
                    $null
                }
                'Local'{
                    switch ($runningUserDomainSuffix -eq $upnSuffix){
                        $True{Set-AdUser $usertoModify -add @{"proxyAddresses"="$($inputAlias)"} -ErrorAction Stop}
                        $false{Set-AdUser $usertoModify -add @{"proxyAddresses"="$($inputAlias)"} -ErrorAction Stop -Server $upnSuffix -ErrorAction Stop}
                    }
                }
            }
            Write-Output "$aliasType Alias now $inputAlias"
        }
    }
    function Invoke-uniqueParentCompanySync{
        [CmdletBinding()]
        param(
        [Parameter(Position = 2, HelpMessage = "Enter the name of the sever that syncs devices. Example: US-TT-VS-AADC01.uniqueParentCompany.com`n`nEnter")]
        [string] $syncServer = "US-TT-VS-AADC01.uniqueParentCompany.com"
        )
        #Ensures you aren't going to wait over 5 minutes for a sync, if it takes over 5 minutes, something is wrong.
        $waitedTime = 0
        try{
            Invoke-Command -ComputerName $syncServer -ScriptBlock {Start-AdSyncSyncCycle -PolicyType Delta} -erroraction Stop
            Write-Output "Sync started! It can take up to 5 minutes to apply"
        }
        catch{
            $busySync = $true
            while ($busySync -or ($waitedTime -lt 50))
            {
                $syncErrorMessage = ($error[0] | Select-Object exception).exception
                If (Select-String -InputObject $syncErrorMessage -Pattern "The user name or password is incorrect.")
                {
                    Write-Output "Your entered credentials are invalid!"
                    $uniqueParentCompanyCred = Get-Credential -Message "Enter your uniqueParentCompany Admin Account Credentials that can remote into the AADC server.  The notation to use is Test.User@uniqueParentCompany.com"
                    $error.Clear()
                }
                else
                {
                    Write-Output "Waiting 10 seconds for Sync to Finish at $(Get-Date -Format HH:mm:ss)"
                    $waitedTime++
                    Start-Sleep -Seconds 6
                    $syncResult = Invoke-Command -ComputerName $syncServer -ScriptBlock {Start-AdSyncSyncCycle -PolicyType Delta} -Credential $uniqueParentCompanyCred -ErrorAction SilentlyContinue
                    if ($syncResult.Result -eq "Success")
                    {
                        $busySYnc = $false
                    }
                }
            }
            if($waitedTime -eq 50){Write-Output "Somethning is wrong with the sync."}
            else{Write-Output "Sync ran at $(Get-Date -Format HH:mm:ss), it will take up to 5 minutes for all changes to replicate"}
        }
    }
    function Set-NewUserDataPath {
        [CmdletBinding()]
        param(
        [Parameter(Position = 0, HelpMessage = "Enter the Path of the Current User Data Drive Directory, leading up to their user account. `nExample: \\directory\share\`nEnter",Mandatory = $true)]
        [string]$userDataPath,
        [Parameter(Position = 1, HelpMessage = "Enter the Previous Username`nExample: testUser`nEnter",Mandatory = $true)]
        [string]$previousName,
        [Parameter(Position = 2, HelpMessage = "Enter the New Username`nExample: Test.User`nEnter",Mandatory = $true)]
        [string]$newUserName
        )
        if ($userDataPath.EndsWith("\")){
                $confirmedTerminatingUserPath = $userDataPath
            }
        else{
            $confirmedTerminatingUserPath = $userDataPath , "\" -join ""
        }
        if(!(Test-Path $confirmedTerminatingUserPath -ErrorAction SilentlyContinue)){Write-Warning "No User Directory Found, no rename has occured."}
        Else{
            $oldUserPath = $confirmedTerminatingUserPath , $previousName -join ""
            if(!(Test-Path $oldUserPath)){Write-Warning "Failed to find $oldUserPath, no rename has occured."}
            else{
                try{
                    $newUserPath = $confirmedTerminatingUserPath , $newUserName -join ""
                    Rename-Item -Path $userDataPath -NewName $newUserPath
                    Write-Output "Verify $newUserName can access $newUserPath"
                }
                catch{
                    Write-Warning "Failed to rename $oldUserPath to $newUserPath, perform manual troubleshooting."
                }
            }
        }
    }

    $isFinished = $False
    Write-Output "Welcome $($env:USERNAME) to the uniqueParentCompany User Renamer!"
    Do{
    $runningUserDomainSuffix = "@" , $env:USERDNSDOMAIN -join ""
    # Output the domain suffix

    $GRAPHOrLocal = $null
    $userExists = $false
    $usertoModify = $null
    $scopes = $null
    $contexts = $null
    $contexts = Get-MGContext
    If ($null -eq $contexts){
    Write-Output "Attempting to connect to Graph"
    $graphTokenRequest = Invoke-WebRequest -Method Post -Uri $graphURI -ContentType "application/x-www-form-urlencoded" -Body $graphAuthBody -UseBasicParsing

    # Extract the Access Token
    $graphSecureToken = ($graphTokenRequest.content | convertfrom-json).access_token | ConvertTo-SecureString -AsPlainText -force
    Write-Output "Attempting to connect to Graph"
    Connect-MgGraph -NoWelcome -AccessToken $graphSecureToken -ErrorAction Stop
    }
    $scopes = Get-MGcontext | Select-Object -ExpandProperty Scopes
    If ($scopes -notcontains 'User.ReadWrite.All'){
        Throw 'Insufficient privileges. Please PIM, use a different account, or contact GHD'
    }
    try{
    $graphUser = Get-MGBetaUser -userid $currentUserName -ErrorAction Stop | select-object *
    if ($graphUser.OnPremisesSyncEnabled){$graphOrLocal =2}
    else{$graphOrLocal = 1}
    }
    catch{
        $graphOrLocal = 2
    }

    If ($graphOrLocal -eq 2){
        do{
            $userToModify = Get-ADUser -Filter "UserPrincipalName -eq '$currentUserName'" -properties * -erroraction SilentlyContinue
            if ($null -ne $userToModify)
            {
                $userExists = $true
                Write-Output "User Mapped. Proceeding"
            }
            Else
            {
                switch ($auto) {
                    $true {Throw "Attempting to find $currentUserName Failed"
                    }
                    Default {
                        Write-Output "No user found with Username: $currentUserName Please try again`n`n`n"
                        $currentUserName = Read-Host -Prompt "Enter the UPN of the user to fix"
                    }
                }
            }
        } While ($userExists -eq $false)
        $upnSuffix = ($usertoModify.userPrincipalName -replace '^[^@]+', '').ToUpper()
        Write-Output "User Information is as follows:"
        Write-Output "User's FirstName: $($usertoModify.GivenName)"
        Write-Output "User's LastName: $($usertoModify.Surname)"
        Write-Output "User's DisplayName: $($usertoModify.DisplayName)"
        Write-Output "User's UPN: $($usertoModify.UserPrincipalName)"
        Write-Output "User's UPN Suffix: $upnSuffix"
        Write-Output "User's Aliases: $($usertoModify.proxyAddresses)"
        Write-Output "User's SAM Account Name: $($usertoModify.SamAccountName)"
        Write-Output "User's Distinguished Name: $($usertoModify.DistinguishedName)"
        

        $givenName = $userToModify.GivenName
        $surName = $usertoModify.Surname
        $oldSAM = $userToModify.SamAccountName
        $oldUPN = $userToModify.UserPrincipalName
        $currentAliases = $usertomodify.proxyAddresses
        $newAlias = "smtp:"+$oldUPN
        $firstNameFormatted = Format-Name -inputName $givenName
        $lastNameFormatted = Format-NAme -inputName $surName
        write-output "First Name Formatted: $firstNameFormatted `nLast Name Formatted: $lastNameFormatted"
        $newdisplayName = $firstNameFormatted , $lastNameFormatted -join " "
        $mailNN = ($firstNameFormatted + "." +$lastNameFormatted).replace(" ","")
        $mailNN = $mailNN.trim()
        [string]$testNewUPN = $mailNN , $upnSuffix -join ""
        If ($mailNN.length -gt 20)
        {
            $newSAMName = $mailNN.substring(0,20)
        }

        Else
        {
            $newSAMName = $mailNN
        }

        Write-Output "`n`n`n`nUser Information POST CHANGES WILL BE as follows:"
        Write-Output "User's NEW FirstName:         $firstNameFormatted"
        Write-Output "User's NEW LastName:          $lastNameFormatted"
        Write-Output "User's NEW DisplayName:       $newDisplayName"
        Write-Output "User's NEW UPN:               $testNewUPN"
        Write-Output "User's NEW SAM Account Name:  $newSAMName"
        Write-Output "User's ADDED Aliases:         $newAlias"
        Write-Output "User's Redirected Drive:      $userDataDirectory"

        if (($auto) -and ($custom)){$confirmation = "E"}
        elseif (($auto) -and (!($custom))){$confirmation = "Y"}
        else{$confirmation = Read-Host "`n`nWould you like to process these changes? Y for Yes, N, for No, E to Edit Manually"}

        #Auto Accept
        If($confirmation.substring(0,1) -eq 'Y'){
                [string]$newUPN = $mailNN , $upnSuffix -join ""
                $primaryAlias = "SMTP:"+$newUPN
                try{
                    if ($primaryAlias -eq $newAlias){
                        $primaryAlias | ForEach-Object {Add-Alias -inputAlias $_ -GraphOrLocal "Local" -ErrorAction Stop}
                    }
                    else{
                        $newAlias , $primaryAlias| ForEach-Object {Add-Alias -inputAlias $_ -GraphOrLocal "Local" -ErrorAction Stop}
                    }
                }
                catch{
                    Throw $error[0].exception.message   
                }
                try{
                    switch ($runningUserDomainSuffix -eq $upnSuffix){
                        $True{Set-AdUser $usertoModify -userprincipalname $newUPN -SamAccountName $newSAMName -emailAddress $newUPN -DisplayName $newDisplayName -GivenName $firstNameFormatted -Surname $lastNameFormatted -Replace @{"MailNickName"="$newDisplayName"} -ErrorAction Stop}
                        $false{Set-AdUser $usertoModify -userprincipalname $newUPN -SamAccountName $newSAMName -emailAddress $newUPN -DisplayName $newDisplayName -GivenName $firstNameFormatted -Surname $lastNameFormatted -Replace @{"MailNickName"="$newDisplayName"} -Server $upnSuffix -ErrorAction Stop}
                    }
                }
                catch{
                    Throw $error[0].exception.message
                }
                try{
                    switch ($runningUserDomainSuffix -eq $upnSuffix){
                        $True{$userChanged = Get-ADUser $newSAMName -properties * -ErrorAction Stop
                            Rename-ADObject -Identity $userChanged.DistinguishedName -NewName $newDisplayName -ErrorAction Stop
                            $userChanged = Get-ADUser $newSAMName -properties * -ErrorAction Stop}
                        $false{$userChanged = Get-ADUser $newSAMName -properties * -Server $upnSuffix -ErrorAction Stop
                            Rename-ADObject -Identity $userChanged.DistinguishedName -NewName $newDisplayName -Server $upnSuffix -ErrorAction Stop
                            $userChanged = Get-ADUser $newSAMName -properties * -Server $upnSuffix -ErrorAction Stop}
                    }
                    Write-Output "`n`n`n`nUser Information POST CHANGES are as follows:"
                    Write-Output "User's UPN: $($userChanged.UserPrincipalName)"
                    Write-Output "User's Aliases: $($userChanged.proxyAddresses)"
                    Write-Output "User's SAM Account Name: $($userChanged.SamAccountName)"
                    Write-Output "User's Distinguished NAme: $($userChanged.DistinguishedName)"
                    Invoke-uniqueParentCompanySync
                }
                catch{
                    Throw $error[0].exception.message
                }    
            }
        
                #Manual Edits
                ElseIf ($confirmation.substring(0,1) -eq 'E'){
                    try{
                        switch("" -eq $newUPN){
                            $true {$newUPN = Read-Host "Enter the New UPN"}
                            Default {$null}
                        }
                        switch ("" -eq $firstName) {
                             $true {$firstName = Read-Host "Enter the User's Preferred Given Name"}
                            Default {$null}
                        }
                        switch ("" -eq $lastName) {
                            $true {$lastName = Read-Host "Enter the User's Surname"}
                            Default {$null}
                        }                        
                        
                        #nameFunctionality
                        $oldSAM = $userToModify.SamAccountName
                        $oldUPN = $userToModify.UserPrincipalName
                        $currentAliases = $usertomodify.proxyAddresses
                        $newAlias = "smtp:"+$oldUPN
                        $firstNameFormatted = Format-Name -inputName $firstName
                        $lastNameFormatted  = Format-Name -inputName $lastName
                        $newdisplayName = $firstNameFormatted , $lastNameFormatted -join " "
                        $newSAMName = $newUPN.Split('@')[0]
                        If ($newSAMName.length -gt 20){
                            $newSAMName = $newSAMName.substring(0,20)
                        }
                        Write-Output "`n`n`n`nUser Information POST CHANGES WILL BE as follows:"
                        Write-Output "User's NEW FirstName:     $firstNameFormatted"
                        Write-Output "User's NEW LastName:      $firstNameFormatted"
                        Write-Output "User's NEW DisplayName:   $newDisplayName"
                        Write-Output "User's NEW UPN:           $newUPN"
                        Write-Output "User's NEW SAM Account Name: $newSAMName"
                        Write-Output "User's ADDED Aliases:     $newAlias"
                        
                        $primaryAlias = "SMTP:"+$newUPN
                        if ($primaryAlis -eq $newAlias){
                            $primaryAlias | ForEach-Object {Add-Alias -inputAlias $_ -GraphOrLocal "Local" -ErrorAction Stop}
                        }
                        else{
                            $newAlias , $primaryAlias | ForEach-Object {Add-Alias -inputAlias $_ -GraphOrLocal "Local" -ErrorAction Stop}
                        }
                        switch ($runningUserDomainSuffix -eq $upnSuffix){
                            $True{Set-AdUser $usertoModify -userprincipalname $newUPN -SamAccountName $newSAMName -emailAddress $newUPN -DisplayName $newDisplayName -GivenName $firstNameFormatted -Surname $lastNameFormatted -Replace @{"MailNickName"="$newDisplayName"} -ErrorAction Stop}
                            $false{Set-AdUser $usertoModify -userprincipalname $newUPN -SamAccountName $newSAMName -emailAddress $newUPN -DisplayName $newDisplayName -GivenName $firstNameFormatted -Surname $lastNameFormatted -Replace @{"MailNickName"="$newDisplayName"} -Server $upnSuffix -ErrorAction Stop}
                        }
                        switch ($runningUserDomainSuffix -eq $upnSuffix){
                            $True{$userChanged = Get-ADUser $newSAMName -properties * -ErrorAction Stop
                                Rename-ADObject -Identity $userChanged.DistinguishedName -NewName $newDisplayName -ErrorAction Stop
                                $userChanged = Get-ADUser $newSAMName -properties * -ErrorAction Stop}
                            $false{$userChanged = Get-ADUser $newSAMName -properties * -Server $upnSuffix -ErrorAction Stop
                                Rename-ADObject -Identity $userChanged.DistinguishedName -NewName $newDisplayName -Server $upnSuffix -ErrorAction Stop
                                $userChanged = Get-ADUser $newSAMName -properties * -Server $upnSuffix -ErrorAction Stop}
                            }

                        Write-Output "`n`n`n`nUser Information POST CHANGES are as follows:"
                        Write-Output "User's UPN: $($userChanged.UserPrincipalName)"
                        Write-Output "User's Aliases: $($userChanged.proxyAddresses)"
                        Write-Output "User's SAM Account Name: $($userChanged.SamAccountName)"
                        Write-Output "User's Distinguished NAme: $($userChanged.DistinguishedName)"
                        Set-NewUserDataPath -userDataPath $userDataDirectory -previousName $oldSAM -newUserName $newSAMName
                    }
                    catch{  
                        Throw $error[0]
                    }
                }
                #Exit
                ElseIf ($confirmation.substring(0,1) -eq 'N')
                {
                    Throw "Aborting Changes."
                }
                #Invalid Entries
                ElseIf (($confirmation.substring(0,1) -ne 'E') -and ($confirmation.substring(0,1) -ne 'Y') -and ($confirmation.substring(0,1) -ne 'N'))
                {
                    Write-Output "Invalid Selection, Aborting Changes"
                }
    
    }
    elseIf ($graphOrLocal -eq 1)
    {
        $contexts = Get-MGContext
        If ($null -eq $contexts)
        {
        $graphTokenRequest = Invoke-WebRequest -Method Post -Uri $graphURI -ContentType "application/x-www-form-urlencoded" -Body $graphAuthBody -UseBasicParsing

        # Extract the Access Token
        $graphSecureToken = ($graphTokenRequest.content | convertfrom-json).access_token | ConvertTo-SecureString -AsPlainText -force
        Write-Output "Attempting to connect to Graph"
        Connect-MgGraph -NoWelcome -AccessToken $graphSecureToken -ErrorAction Stop
        }
        $scopes = Get-MGcontext | Select-Object -ExpandProperty Scopes
        If ($scopes -notcontains 'User.ReadWrite.All')
        {
            Throw 'Insufficient privileges. Please PIM, use a different account, or contact GHD'
        }
        Else{
            do{
                $userToModify = Get-MGBetaUser -userid "$currentUserName" -property * -erroraction SilentlyContinue
                if ($null -ne $userToModify)
                {
                    $userExists = $true
                    Write-Output "User Mapped. Proceeding"
                }
                Else
                {
                    switch ($auth) {
                        $true {Throw "No user found with Username: $currentUserNAme on Microsoft Graph"}
                        Default {Write-Output "No user found with Username: $currentUserName Please try again`n`n`n"
                        $currentUserName = Read-Host -Prompt "Enter the UPN of the user to fix"}
                    }

                }
            } While ($userExists -eq $false)


            Write-Output "User Information is as follows:"
            Write-Output "User's UPN: $($usertoModify.UserPrincipalName)"
            Write-Output "User's Aliases: $($usertoModify.proxyAddresses)"

            $givenName = $userToModify.GivenName
            $surName = $usertoModify.Surname
            $oldUPN = $userToModify.UserPrincipalName
            $currentAliases = $usertomodify.proxyAddresses
            $newdisplayName = $firstNameFormatted , $lastNameFormatted -join " "
            $newAlias = "smtp:"+$oldUPN
            $upnSuffix ="@" +$usertoModify.userPrincipalName.Split('@')[1]
            $firstNameFormatted = Format-Name -inputName $givenName
            $lastNameFormatted  = Format-Name -inputName $surName
            $newdisplayName = $firstNameFormatted , $lastNameFormatted -join " "
            $mailNN = ($firstNameFormatted + "."+$lastNameFormatted).replace(" ","")
            $mailNN = $mailNN.trim()
            [string]$testNewUPN = $mailNN , $upnSuffix -join ""
            Write-Output "`n`n`n`nUser Information POST CHANGES WILL BE as follows:"
            Write-Output "User's NEW UPN: $testNewUPN"
            Write-Output "User's ADDED Aliases: $newAlias"

            if (($auto) -and ($custom)){$confirmation = "E"}
            elseif(!($auto) -and ($custom)){$confirmation = "E"}
            elseif (($auto) -and (!($custom))){$confirmation = "Y"}
            else{$confirmation = Read-Host "`n`nWould you like to process these changes? Y for Yes, N, for No, E to Edit Manually"}
                 
            If ($confirmation.substring(0,1) -eq 'Y'){
                $newUPN = $testNewUPN
                $primaryAlias = "SMTP:"+$newUPN
                if ($primaryAlis -eq $newAlias){
                        $primaryAlias | ForEach-Object {Add-Alias -inputAlias $_ -GraphOrLocal "Graph" -ErrorAction Stop}
                    }
                    else{
                        $newAlias , $primaryAlias | ForEach-Object {Add-Alias -inputAlias $_ -GraphOrLocal "Graph" -ErrorAction Stop}
                    }
                    $graphUserID = $usertoModify.Id

                    #Request a Token for the Graph API Pushes
                    $tokenRequest = Invoke-WebRequest -Method Post -Uri $graphURI -ContentType "application/x-www-form-urlencoded" -Body $graphAuthBody -UseBasicParsing
                    # Extract the Access Token
                    $baseToken = ($tokenRequest.content | convertfrom-json).access_token
    
                    $graphAPIHeader = @{
                        "Authorization" = "Bearer $baseToken"
                        "Content-Type" = "application/JSON"
                        grant_type    = "client_credentials"
                    }
    
    
                    $uniqueParentCompanyRenameHashtable = @{
                        UserPrincipalName   =   "$newUPN"
                        GivenName           =   "$firstNameFormatted"
                        SurName             =   "$lastNameFormatted"
                        DisplayName         =   "$newDisplayName"
                        MailNickName        =   "$mailNN"
                    }
                $uniqueParentCompanyRenameJSON = $uniqueParentCompanyRenameHashTable | ConvertTo-JSON -Depth 1
                #Building the URI for the user update
                $baseGraphAPI = "https://graph.microsoft.com/"
                $APIVersion = "v1.0/"
                $endPoint = "users/"
                $target = "$graphUserID"
                $userGraphURI = $baseGraphAPI , $APIVersion , $endpoint , $target -join ""
                #Performs the update to the users for all non-extension attributes
                Invoke-RestMethod -uri $userGraphURI -Method Patch -Body $uniqueParentCompanyRenameJSON -Headers $graphAPIHeader -Verbose -Debug
                $userChanged = Get-MGBetaUser -UserId $newUPN | Select-Object *
                Write-Output "`n`n`n`nUser Information POST CHANGES are as follows:"
                Write-Output "User's UPN: $($userChanged.UserPrincipalName)"
                Write-Output "User's Aliases: $($userChanged.proxyAddresses)"
                Write-Output "User's SAM Account Name: $($userChanged.SamAccountName)"
                }
                ElseIf ($confirmation.substring(0,1) -eq 'E'){
                    switch("" -eq $newUPN){
                        $true {$newUPN = Read-Host "Enter the New UPN"}
                        Default {$null}
                    }
                    switch ("" -eq $firstName) {
                        $true {$firstName = Read-Host "Enter the User's Preferred Given Name"}
                        Default {$null}
                    }
                    switch ("" -eq $lastName) {
                        $true {$lastName = Read-Host "Enter the User's Surname"}
                        Default {$null}
                    }
                $newSAMName = $newUPN.split('@')[0]
                If ($newSAMName.length -gt 20){
                    $newSAMName = $newSAMName.substring(0,20)
                }
                $firstNameFormatted = Format-Name -inputName $firstName
                $lastNameFormatted  = Format-Name -inputName $lastName
                $newdisplayName = $firstNameFormatted , $lastNameFormatted -join " "
                $mailNN = ($firstNameFormatted , $lastNameFormatted -join ".").replace(" ","")
                $primaryAlias = "SMTP:"+$newUPN
                $graphUserID = $usertoModify.Id

                #Request a Token for the Graph API Pushes
                $tokenRequest = Invoke-WebRequest -Method Post -Uri $graphURI -ContentType "application/x-www-form-urlencoded" -Body $graphAuthBody -UseBasicParsing
                # Extract the Access Token
                $baseToken = ($tokenRequest.content | convertfrom-json).access_token

                $graphAPIHeader = @{
                    "Authorization" = "Bearer $baseToken"
                    "Content-Type" = "application/JSON"
                    grant_type    = "client_credentials"
                }


                $uniqueParentCompanyRenameHashtable = @{
                    UserPrincipalName   =   "$newUPN"
                    GivenName           =   "$firstNameFormatted"
                    SurName             =   "$lastNameFormatted"
                    DisplayName         =   "$newDisplayName"
                    MailNickName        =   "$mailNN"
                }
                $uniqueParentCompanyRenameJSON = $uniqueParentCompanyRenameHashTable | ConvertTo-JSON -Depth 1
                #Building the URI for the user update
                $baseGraphAPI = "https://graph.microsoft.com/"
                $APIVersion = "v1.0/"
                $endPoint = "users/"
                $target = "$graphUserID"
                $userGraphURI = $baseGraphAPI , $APIVersion , $endpoint , $target -join ""
                #Performs the update to the users for all non-extension attributes
                Invoke-RestMethod -uri $userGraphURI -Method Patch -Body $uniqueParentCompanyRenameJSON -Headers $graphAPIHeader -Verbose -Debug
                if ($primaryAlis -eq $newAlias){
                    $primaryAlias | ForEach-Object {Add-Alias -inputAlias $_ -GraphOrLocal "Graph" -ErrorAction Stop}
                }
                else{
                    $newAlias , $primaryAlias | ForEach-Object {Add-Alias -inputAlias $_ -GraphOrLocal "Graph" -ErrorAction Stop}
                }
                $userChanged = Get-MGBetaUser -userid $newUPN -property *
                Write-Output "`n`n`n`nUser Information POST CHANGES are as follows:"
                Write-Output "User's UPN: $($userChanged.UserPrincipalName)"
                Write-Output "User's Aliases: $($userChanged.proxyAddresses)"
                }
                ElseIf ($confirmation.substring(0,1) -eq 'N'){
                    Write-Output "Aborting Changes."
                }
                ElseIf(($confirmation.substring(0,1) -ne 'E') -and ($confirmation.substring(0,1) -ne 'Y') -and ($confirmation.substring(0,1) -ne 'N')){
                    Write-Output "Invalid Selection, Aborting Changes"
                }
        }
    }

    Elseif (($graphOrLocal -ne 1) -and ($graphOrLocal -ne 2))
    {
        Write-Output 'Invalid Selection'
    }
                
                switch ($auto){
                    $true{$rerun = "N"}
                    Default{$rerun = Read-Host "Would you like to rerun the script? Y for Yes, N, or any other Letter, for No"}
                }
                If ($rerun.substring(0,1) -eq 'Y')
                {
                    $userToModify = $null
                    $currentUserName = $null
                    $newUPN = $null
                    $firstName = $null
                    $lastName = $null
                    $graphOrLocal = $null
                    $isFinished = $False
                }
                Else
                {
                    $isFinished = $True
                }

    $graphOrLocal = $null
    }
    while ($isFinished -ne $True)
}
Import-module Az.Accounts
Import-Module Az.KeyVault
Import-Module Microsoft.Graph.Users
#onPremConnection and Data Review
try {
    # Read from Azure Key Vault using managed identity
    connect-azaccount -subscription 'ea460e20-c6e3-46c7-9157-101770757b6b' -Identity | out-null
    
}
catch {
    $errorMessage = $_
    Write-Output $errorMessage

    $ErrorActionPreference = "Stop"
}
    #Connect to: Graph / Via: Secret
    #The Tenant ID from App Registrations
    $graphTenantId = "9e228334-bae6-4c7e-8b7f-9b0824082151"

    # Construct the authentication URL
    $graphURI = "https://login.microsoftonline.com/$graphTenantId/oauth2/v2.0/token"
    
    #The Client ID from App Registrations
    $graphAppClientId = "56cb7f72-67ee-4531-96d7-39a4e2b53555"
    
    $graphRetrSecret = Get-AzKeyVaultSecret -VaultName "US-TT-VAULT" -Name "GITGraphApi" -AsPlainText
    
    # Construct the body to be used in Invoke-WebRequest
    $graphAuthBody = @{
        client_id     = $graphAppClientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret =  $graphRetrSecret
        grant_type    = "client_credentials"
    }
    
    
# Get Authentication Token
$graphTokenRequest = Invoke-WebRequest -Method Post -Uri $graphURI -ContentType "application/x-www-form-urlencoded" -Body $graphAuthBody -UseBasicParsing

# Extract the Access Token
$graphSecureToken = ($graphTokenRequest.content | convertfrom-json).access_token | ConvertTo-SecureString -AsPlainText -force
Write-Output "Attempting to connect to Graph"
Connect-MgGraph -NoWelcome -AccessToken $graphSecureToken -ErrorAction Stop
#Connect to Jira via the API Secret in the Key Vault
$jiraRetrSecret = Get-AzKeyVaultSecret -VaultName "US-TT-Vault" -Name "JiraAPI" -AsPlainText
#Jira
$jiraText = "david.drosdick@uniqueParentCompany.com:$jiraRetrSecret"
$jiraBytes = [System.Text.Encoding]::UTF8.GetBytes($jiraText)
$jiraEncodedText = [Convert]::ToBase64String($jiraBytes)
$jiraHeader = @{
    "Authorization" = "Basic $jiraEncodedText"
    "Content-Type" = "application/json"
}
$originUser = Get-MgUser -UserId $originUPN -property * | Select-Object -Property * 
Write-Output "Origin User:"
$originUser | Format-List
$originID = $originUser.ID
$ParamsForRunbook = @{}
$parameters = Get-Member -InputObject $paramsFromTicket | Where-Object {($_.MemberType -like "*Property*")} | Select-Object Name , MemberType

#Building the URI for the user update
$baseGraphAPI = "https://graph.microsoft.com/"
$APIVersion = "v1.0/"
$endPoint = "users/"
$target = "$originID"
$userGraphURI = $baseGraphAPI , $APIVersion , $endpoint , $target -join ""



Write-Output "$`paramsFromTicket is $($paramsFromTicket.GetType())"
Write-Output "Params From Ticket Prior to Sanitization:"
$paramsFromTicket | Format-List

if ($Parameters.Name -like "*ExtensionAttribute*"){
    $extensionAttributes = @{}
    # Extract only properties that match "ExtensionAt*" and convert them into a hashtable
    $paramsFromTicket.PSObject.Properties | ForEach-Object {
        if ($_.Name -like "ExtensionAt*"){
            $extensionAttributes[$_.Name] = $_.Value
        }
    }
    $paramsFromTicket = $paramsFromTicket | Select-Object -ExcludeProperty "ExtensionAt*"
    $paramsFromTicket.psobject.properties | ForEach-Object { $ParamsForRunbook[$_.Name] = $_.Value }
    Write-Output "Extension Attributes:"
    $extensionAttributes | Format-List

    
    switch ($extensionAttributes.ExtensionAttribute1){
        "Shop" {
            $license1 = "SPE_F1"
            $licStr="F3"
            $removingLicense = "SPE_E5"
        }
        "Office" {
            $license1 = "SPE_E5"
            $licStr = "E5"
            $removingLicense = "SPE_F1"
        }
        "Shop Office" {
            $license1 = "SPE_E5"
            $licStr = "E5"
            $removingLicense = "SPE_F1"
        }
    }
    Write-Output "License to add: $license1"
    Write-Output "License String: $licStr"
    Write-Output "Removing License: $removingLicense"
    $sku1 = Get-MgSubscribedSku -All | Where-Object -Property SkuPartNumber -eq $license1
    $remLisc = $sku1.prepaidunits.enabled - $sku1.consumedunits 
    if ($remlisc -le 0){ 
        Write-Output "$licStr Needs Purchased"
        Set-LicenseNeedPurchased -Continue=$true -license $licStr
    }
    Else{
        Write-Output "Assessing $($originUser.DisplayName) for $license1"
    }
    $assignedLicenses = Get-MgUserLicenseDetail -userid $originUPN
    if ($null -eq $assignedLicenses){
        Write-Output "$($originUser.DisplayName) does not have any licenses assigned."
        Set-MgUserLicense -UserId $originUPN -AddLicenses @{SkuId = $sku1.SkuId} -RemoveLicenses @()
    }
    ElseIf ($assignedLicenses.SkuPartNumber -notcontains $license1){
        $removalLicense = Get-MgSubscribedSku -All | Where-Object -Property SkuPartNumber -eq $removingLicense
        Set-MgUserLicense -UserId $originUPN -AddLicenses @{SkuId = $sku1.SkuId} -RemoveLicenses @($removalLicense.SkuId)
    }
    Else{
        Write-Output "$($originUser.DisplayName) has the proper license assigned!"
    }
}


if($parameters.Name -like "*BusinessPhones*"){ 
    $businessPhones = @{}
   $paramsFromTicket.PSObject.Properties | ForEach-Object {
        if ($_.Name -like "*BusinessPhones*"){
            $businessPhones[$_.Name] = $_.Value
        }
    }
    $updateBody = @{
        businessPhones = @($businessPhones.businessPhones)  # Replace the existing phone number
    } | ConvertTo-Json -Depth 2
    #Request a Token for the Graph API Pushes
    $tokenRequest = Invoke-WebRequest -Method Post -Uri $graphURI -ContentType "application/x-www-form-urlencoded" -Body $graphAuthBody -UseBasicParsing
    # Extract the Access Token
    $baseToken = ($tokenRequest.content | convertfrom-json).access_token

    $graphAPIHeader = @{
        "Authorization" = "Bearer $baseToken"
        "Content-Type" = "application/JSON"
        grant_type    = "client_credentials"
    }
    Invoke-RestMethod -Method Patch -uri $userGraphURI -Body $updateBody -Headers $graphAPIHeader
    
    $paramsFromTicket = $paramsFromTicket | Select-Object -ExcludeProperty "BusinessPhones*"
    $paramsFromTicket.psobject.properties | ForEach-Object { $ParamsForRunbook[$_.Name] = $_.Value }
}
if($parameters.Name -notlike "*UPNSUffix*" -and $parameters.Name -notlike "*ExtensionAttribute*" -and $parameters.Name -notlike "*BusinessPhones*"){ 
        $paramsFromTicket.psobject.properties | ForEach-Object { $ParamsForRunbook[$_.Name] = $_.Value }
}
$paramsForRunbook.remove("UserID")
Write-Output "This is post santization"
Write-Output "$`paramsForRunbook is $($paramsForRunbook.GetType())"
Write-Output "The Passed Parameters are as Follows:"
$ParamsForRunbook | Select-Object * | Format-List


If (($newManagerUPN -ne "") -and ($null -ne $newManagerUPN))
{
Write-Output "`nThe New Manager UPN is: $newManagerUPN"
$managerID = (Get-MGUser -Search "UserPrincipalName:$($newManagerUPN)" -ConsistencyLevel:eventual -top 1).ID 

#Sets the Manager ID
$managerJSON = @{
"@odata.id" = "https://graph.microsoft.com/v1.0/users/$ManagerId"
} | ConvertTo-JSON -Depth 1
$updateManagerURI = $userGraphURI , "/Manager/$","ref" -join ""

Invoke-RestMethod -uri $updateManagerURI -Method Put -Body $managerJSON -Headers $graphAPIHeader -Verbose -Debug


}

Write-Output "Writing the Splat:`n"
Write-Output @ParamsForRunbook

try{
    #Request a Token for the Graph API Pushes
    $tokenRequest = Invoke-WebRequest -Method Post -Uri $graphURI -ContentType "application/x-www-form-urlencoded" -Body $graphAuthBody -UseBasicParsing
    # Extract the Access Token
    $baseToken = ($tokenRequest.content | convertfrom-json).access_token

    $graphAPIHeader = @{
        "Authorization" = "Bearer $baseToken"
        "Content-Type" = "application/JSON"
        grant_type    = "client_credentials"
    }
    $paramsForRunbookJSON = $ParamsForRunbook | ConvertTo-JSON
    #Performs the update to the users for all non-extension attributes
    Invoke-RestMethod -uri $userGraphURI -Method Patch -Body $paramsForRunbookJSON -Headers $graphAPIHeader -Verbose -Debug
    if ($extensionAttributes)
    {
        Update-MgBetaUser -userid $originID -OnPremisesExtensionAttributes $extensionAttributes -errorAction Stop
        $updatedGraphUser = Get-MGBetaUser -userid $originID -errorAction Stop
        $updatedUserLicenses = Get-MGUserLicenseDetail -userid $updatedGraphUser.UserPRincipalName -erroraction Stop
        if (($updatedGraphUser.UsageLocation -in "IT","CA","BE","AU","DE","DK","VN","AE","MY","GB","ZA") -and ($updatedUserLicenses.SkuPartNumber -notcontains 'OFFICE365_MULTIGEO')){
        $sku3 = Get-MgSubscribedSku -All |  Where-Object -Property SkuPartNumber -eq 'OFFICE365_MULTIGEO'
        $remLisc = $sku3.prepaidunits.enabled - $sku3.consumedunits
            if ($remlisc -le 0)
            { 
                WRite-Output "OFFICE365_MULTIGEO Needs Purchased $displayName"
                Set-LicenseNeedPurchased -license "OFFICE365_MULTIGEO" -Continue:$true
            }
            Else
            {
                    Set-MgUserLicense -UserId $updatedGraphUser.id -AddLicenses @{SkuId = $sku3.SkuId} -RemoveLicenses @()
            }
        }
        Else{
            Write-Output "A Multi-Geo License is Not Required for $($updatedGraphUser.DisplayName)"
        }
    }
    #Renames the user, changing their UPN, email, and display names
    Rename-uniqueParentCompanyUser -currentUserName $originUPN -auto -ErrorAction Stop
    if ($isTransfer -eq "Yes"){
        Write-Output "This is a transfer and one more step remains"
    }
    else{
    Set-SuccessfulCommentRunbook
    }
    }
    catch {
        $errorMessage = $_
        Write-Output $errorMessage    
        $ErrorActionPreference = "Stop"
        Set-PrivateErrorJiraRunbook
        Set-PublicErrorJira
}
# SIG # Begin signature block
# MIIuqwYJKoZIhvcNAQcCoIIunDCCLpgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBrNXlozpRcy8fA
# C2AqDIg383NLd6xLDM+yUZdxqHDyRKCCFAUwggWQMIIDeKADAgECAhAFmxtXno4h
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMYPj0vTCVMm7110UvJkqJck
# jOq7hPslCozgiKIyhvjUMA0GCSqGSIb3DQEBAQUABIICAGEefOkHI9i1E2hFMssz
# 4g8YZT5tf/YkgeviERe7G9nbFnX10q9+c3LU3YOnpF2zKZJY8FgqQ+fxOQB/zqfE
# 1+ThHpPUQKWwMzmjob8slCk3rScbUb0I64J7Uk+kuOlBmutITS24Bmhf5yFinpiX
# zu77wcDTr8ggbrFCtIqFpLK2m8Ls/CqsjQGPuetAnTPJbIoBwrEfcmpyBs0bBWnU
# FFOtT1NxGCxtCLbW3Lg1j/eSA+GAlvJMObPOrJK3/qvuukSw1Buh3az9JLcn1U7k
# VAa03MQe6wTLvL5OoYUnNpohwvEKQwkaFtN7VymGyv7NaPVh7luZMvmLtrzoMLvL
# Iu9qSoHu09hH//I2DFMA1PDPEfrK5SWyVcQsB62sHSBbzALgj23Jy0J6M/jSv8+9
# ntrDXb8/XpRrszuUxUOUbq3hdJVJKIE+quR3l3VG5ITDRteamMemberR4HI24liuPYXdBaA
# xAoQDRGEfs43tvlwbIq2p0rg1bt6I0C8a6O40uEeKqvvMBYD6cg/MeuAvWGzL0GN
# vwcO6ZsuyHzObxlgKJG09TgqxSOeBeviXasMx8YcFE9qUTr+UIPonbcqsvEaMHlz
# QAmRDtyXcK7ACSLyIDGrvLAA+0xZ7xvqtnMKAm08y4/mu278F2F73eLBZULZbI2/
# T36yJWnqxm/I3tH58kYF+c/9oYIWyTCCFsUGCisGAQQBgjcDAwExgha1MIIWsQYJ
# KoZIhvcNAQcCoIIWojCCFp4CAQMxDTALBglghkgBZQMEAgEwgeUGCyqGSIb3DQEJ
# EAEEoIHVBIHSMIHPAgEBBgkrBgEEAaAyAgMwMTANBglghkgBZQMEAgEFAAQgboS+
# 7Nko8fQr2mlvX3I6Rovb7cQYkVdNazyPqbJmpRQCFF9cNgfqg+hz9ZJs58KTWgb8
# fsfMGA8yMDI1MDMwNTE2NTMwMVowAwIBAaBgpF4wXDELMAkGA1UEBhMCQkUxGTAX
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
# 9w0BCQQxIgQgCtOJyM7PTir0ZeQnEFuTlsn498JvGl9tVg1Sk3F1vlMwgbAGCyqG
# SIb3DQEJEAIvMYGgMIGdMIGaMIGXBCALeaI5rkIQje9Ws1QFv4/NjlmnS4Tu4t7D
# 2XHB6hc07DBzMF+kXTBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2ln
# biBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBT
# SEEzODQgLSBHNAIQARl1dHHJktdE36WW67lwFTANBgkqhkiG9w0BAQsFAASCAYAm
# 05GbfDwjIREIMcCBuxmij5KwXepfPti/pFrx+gb7v1xRx9lWx2k8f+IRX0a/fFPc
# E/KBCDznrET296Gfyvv6C9rzfFwV7iiqAJTTrpyJy4qm9W+Do+uBdfxBhnerdaBI
# 1xR5Y53g5rxEP5ToKDDpMdJWVudA7L43eR6HtvJxoaWJlpOwiBykNsOtpzO/qmfd
# 4FVl4/66rH3EA8XLYv5/HG+O0haJnxFmIGei0OdqwgPGr6cP9/IFiJmpWb4beJPv
# 1Gh+b8u//g6Kdqk3nvtIlEb38LCi7NINhqxRBoZgoJ6Y2uY02gDQSmD4Gl5JEJ8e
# TteamMemberG4jPuaJLZfGv1l8E/nyUj0Vq3nNoHNkVaxuUWkr8ehTSb0GVNV3SibamcOep
# mwBXVHNKUaDO4m2sAMtUW76VBvVm0CqdMHoOhLGh1PaOC5vKzt8DMx0pvCblHvMd
# iJhaegqW+tqCmWg08Why2WS4EHoOWVlj10qoTDN52NgSbmJJTeRzwV1PRHqjws4=
# SIG # End signature block




