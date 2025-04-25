param(
    [string] $Key
)
function Set-PrivateErrorJiraRunbook{
    [CmdletBinding()]
    param(
    [Parameter(ParameterSetName = 'Full', Position = 0)]
    [switch]$Continue,
    [Parameter(Position = 1 , HelpMessage = "Enter the Ticket Key. Example: GHD-44881`n`nEnter")]
    [string] $key,
    [Parameter(Position = 2 , HelpMessage = "Enter your Jira Header here")]
    [hashtable] $jiraHeader
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
    Write-Output "[$($currTime)] | Failed. Details Below:"
    Write-Output $errorLog
    switch ($Continue){
        $False {exit 1}
        Default {$null}
    }
}
function Set-PublicErrorJira{
[CmdletBinding()]
param(
[Parameter(ParameterSetName = 'Full', Position = 0)]
[switch]$Continue,
[Parameter(Position = 1, HelpMessage = "Enter the message to include with your Jira Ticket!")]
[string] $publicErrorMessage,
[Parameter(Position = 2 , HelpMessage = "Enter the Ticket Key. Example: GHD-44881`n`nEnter")]
[string] $key,
[Parameter(Position = 3 , HelpMessage = "Enter your Jira Header here")]
[hashtable] $jiraHeader
)
    $jsonPayload = @"
    {
    "update": {
        "comment": [
            {
                "add": {
                    "body": "$publicErrorMessage"
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

function Set-SuccessfulCommentRunbook {
[CmdletBinding()]
param(
[Parameter(ParameterSetName = 'Full', Position = 0)]
[switch]$Continue,
[Parameter(Position = 1, HelpMessage = "Enter the message to include with your Jira Ticket!")]
[string] $successMessage,
[Parameter(Position = 2 , HelpMessage = "Enter the Ticket Key. Example: GHD-44881`n`nEnter")]
[string] $key,
[Parameter(Position = 3 , HelpMessage = "Enter your Jira Header here")]
[hashtable] $jiraHeader
)
$jsonPayload = @"
{
"update": {
"comment": [
    {
        "add": {
            "body": "$successMessage"
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
    Write-Output "[$($currTime)] | Internal Comment Successfully Made with Error Details"
}
} 
catch{
    Write-Output "API call failed: $($_.Exception.Message)"
    Write-Output "Payload: $jsonPayload"
    $currTime = Get-Date -format "HH:mm"
    Write-Output "[$($currTime)] | Failed. Details Below:"
    Write-Output $errorLog
}
switch ($Continue){
    $False {exit 1}
    Default {Continue}
}
}

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

Import-module Az.Accounts
Import-Module Az.KeyVault
Connect-AzAccount -subscription 'ea460e20-c6e3-46c7-9157-101770757b6b' -Identity
Connect-MGGraph -NoWelcome -Identity

#Connect to Jira via the API Secret in the Key Vault
$jiraRetrSecret = Get-AzKeyVaultSecret -VaultName "US-TT-Vault" -Name "JiraAPI" -AsPlainText

$hybridWorkerGroup      = $null
$hybridWorkerCred       = $null
$paramsFromTicket = @{}
$extensionAttributes = @{}


#Jira via the API or by Read-Host 
If ($null -eq $jiraRetrSecret)
{
    $jiraRetrSecret = Read-Host "Enter the API Key" -MaskInput
}
else {
    $null
}



#Jira
$jiraText = "david.drosdick@uniqueParentCompany.com:$jiraRetrSecret"
$jiraBytes = [System.Text.Encoding]::UTF8.GetBytes($jiraText)
$jiraEncodedText = [Convert]::ToBase64String($jiraBytes)
$jiraHeader = @{
    "Authorization" = "Basic $jiraEncodedText"
    "Content-Type" = "application/json"
}
#Pull the values from Jira
$TicketNum = $Key
$Form = Invoke-RestMethod -Method get -uri "https://uniqueParentCompany.atlassteamMember.net/rest/api/2/issue/$TicketNum" -Headers $jiraHeader


$jiraUserToModify   = $form.fields.customfield_10781.emailAddress
$newFirstName       = $form.fields.customfield_10722
$newSurName         = $form.fields.customfield_10723
$newSupervisor      = $form.fields.customfield_10765.emailaddress
$newJobTitle        = $form.fields.customfield_10695
$newCompany         = $form.fields.customfield_10756.value
$shopOrOffice       = $form.fields.customfield_10698.value
$isTransfer         = $form.fields.customfield_10988.value
$officeAppNeeds     = $form.fields.customfield_10751.ID
$officeAppBitType   = $form.fields.customfield_10986.value
$referenceUser = Get-MgBetaUser -userid $jiraUserToModify -property "displayName, userprincipalname, givenname, surname","id","Department","CompanyName" , "JobTitle" , "OfficeLocation", "OnPremisesSyncEnabled", "OnPremisesDomainName" , "OnPremisesSamAccountName" , "OnPremisesExtensionAttributes" | Select-Object *
$originGraphUserID = $referenceUser.ID

#if the user selects 'NO' for 'Is Transfer' there still might be some items that require a transfer to occur.
if ($isTransfer -eq "NO"){
    if ($null -eq $form.fields.customfield_10698.value){
        Write-Output "Determining if Shop or Office, nothing selected in the Jira Ticket."
        If ($null -ne $referenceUser.OnPremisesExtensionAttributes.ExtensionAttribute1){
            $shopOrOffice = $referenceUser.OnPremisesExtensionAttributes.ExtensionAttribute1
            Write-Output "$($referenceUser.DisplayName) is going to be $shopOrOffice, pulled from their existing User Account"
        }
        Else{
            Write-OUtput "$($referenceUser.DisplayName) had nothing selected or configured. We have defaulted to shop"
            $shopOrOffice = "Shop"
        }
    }
    else{
        $ShopOrOffice = $form.fields.customfield_10698.value
        if ($shopOrOffice -eq "Shop"){
            if($officeAppNeeds -eq '10775'){
                $shopOrOffice = "Shop Office"
                if ($referenceUser.OnPremisesSyncEnabled -eq $true){
                $isTransfer = "NO"
                }
                else{
                    $isTransfer = "YES"
                }
            }
        }
        ElseIf(($shopOrOffice -eq 'Office') -and ($referenceUser.OnPremisesExtensionAttributes.ExtensionAttribute1 -eq 'Shop')){
            $isTransfer = "Yes"
        }
        Write-Output "Is Transfer: $isTransfer"
        Write-output "$($referenceUser.DisplayName) is going to be $shopOrOffice per their jira ticket"
    }
}

#Pull the existing user from Graph to determine their type.
$originGraphUserID = $referenceUser.ID
switch ($isTransfer) {
    "YES" {Write-Output "This is a Transfer: $isTransfer"
    $newOfficeLocation  =   $form.fields.customfield_10987.value
    $newDepartment      =   $form.fields.customfield_10987.child.value
    $originLocation =          $referenceUser.OfficeLocation
    $originParametersUser = @{}
    $originParametersObject = @{}
    $destinationLADParameters = @{}
    $destinationGraphParameters = @{}
    $destinationLADExtensionAttributes = @{}

    If ($referenceUser.OnPremisesSyncEnabled -ne $False){
        if ($null -ne $referenceUser.OnPremisesDomainName){
            Write-Output "User is Synching"
            Write-Output "User To Modify:       $jiraUserToModify"
            $samAccountName = $referenceUser.OnPremisesSAMAccountName
            $refUserSynching = $true
            $originSynching = $true
            switch ($isTransfer){
                "Yes"{
                    $originRunbook = "User-Transfer-2-Origin-72"
                    $destinationRunbook = "User-Transfer-2-Destination"
                }
                Default{
                    $runbook = "User-Change-2-LocalAD-72"
                }
            }
        }
    else{
        Write-Output "User is Graph Only"
        Write-Output "User To Modify:       $jiraUserToModify"
        switch ($isTransfer){
            "Yes"{
                $originRunbook = "User-Transfer-2-Origin-72"
                $destinationRunbook = "User-Transfer-2-Destination"
            }
            Default{
                $runbook = "User-Change-2-Graph"  
            }
        }
        $refUserSynching = $false
        $originSynching = $false
        }
    }
    else{
        Write-Output "User is Graph Only"
        Write-Output "User To Modify:       $jiraUserToModify"
        $refUserSynching = $false
        $originSynching = $false
        switch ($isTransfer){
            "Yes"{
                $originRunbook = "User-Transfer-2-Origin-72"
                $destinationRunbook = "User-Transfer-2-Destination"
            }
            Default {
                $runbook = "User-Change-2-Graph"
            }
        }
    }

    #For specific variables related to their origin location if they are synching and need modified.
    switch ($originLocation) {
        "unique-Office-Location-0"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup  = "US-AZ-VS-DC01"
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","uniqueParentCompany.COM")
                    $originParametersObject.Add("Server","uniqueParentCompany.COM")
                    $originParametersObject.Add("TargetPath","OU=XXX-Closed Accounts,DC=uniqueParentCompany,DC=COM")
    
                 }
                $false {
                    $null
                }
            }
        }
        "unique-Office-Location-1"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = "US-CA-VS-DC01"
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","uniqueParentCompanyWest.COM")
                    $originParametersObject.Add("Server","uniqueParentCompanyWest.COM")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")
                 }
                $false {
                $null
                }
            }
        }
        "unique-Office-Location-2"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","uniqueParentCompanyMW.COM")
                    $originParametersObject.Add("Server","uniqueParentCompanyMW.COM")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")

                 }
                $false {
                    $null
                }
            }
        }
        "unique-Office-Location-3"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","uniqueParentCompanyIA.COM")
                    $originParametersObject.Add("Server","uniqueParentCompanyIA.COM")  
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")
                 }
                $false {
                    $null
                }
            }
        }
        "unique-Company-Name-20"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","anonSubsidiary-1CORP.COM")
                    $originParametersObject.Add("Server","anonSubsidiary-1CORP.COM")  
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")  
                    
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Company-Name-7"{
            switch ($refUserSynching) {
                $true { 
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","uniqueParentCompany.BE")
                    $originParametersObject.Add("Server","uniqueParentCompany.BE") 
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")  
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Office-Location-6"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","uniqueParentCompany.IT")
                    $originParametersObject.Add("Server","uniqueParentCompany.IT") 
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")
                 }
                $false {
                    $null
                }
            }
        }
        "uniqueParentCompany (Sondrio) Europe, S.rl.l."{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","uniqueParentCompany.IT")
                    $originParametersObject.Add("Server","uniqueParentCompany.IT")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU") 
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Office-Location-8"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","uniqueParentCompanyCHINA.com")
                    $originParametersObject.Add("Server","uniqueParentCompanyCHINA.com")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU") 
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Office-Location-9"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","uniqueParentCompanyCHINA.com")
                    $originParametersObject.Add("Server","uniqueParentCompanyCHINA.com")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU") 
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Company-Name-3"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","uniqueParentCompany.com.au")
                    $originParametersObject.Add("Server","uniqueParentCompany.com.au")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")  
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Company-Name-18"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "anonSubsidiary-1-Hybrid-Worker"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","anonSubsidiary-1.com") 
                    $originParametersObject.Add("Server","anonSubsidiary-1.com") 
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")  
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Company-Name-5"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "DryCooling-Hybrid-Worker"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","uniqueParentCompanyDC.com")
                    $originParametersObject.Add("Server","uniqueParentCompanyDC.com") 
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")  
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Company-Name-21"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = "US-NC-VS-DC01"
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","@towercomponentsinc.com")
                    $originParametersObject.Add("Server","@towercomponentsinc.com") 
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")   
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Office-Location-27"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","uniqueParentCompanyMW.com")
                    $originParametersObject.Add("Server","uniqueParentCompanyMW.com")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")     

                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Company-Name-6"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","uniqueParentCompany.DK")
                    $originParametersObject.Add("Server","uniqueParentCompany.DK")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")   
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Company-Name-4"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","uniqueParentCompany.com.br")
                    $originParametersObject.Add("Server","uniqueParentCompany.com.br")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")     
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Office-Location-16"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","anonSubsidiary-1.com")
                    $originParametersObject.Add("Server","anonSubsidiary-1.com")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")   
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Company-Name-2"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "Alcoil-Hybrid-Worker"
                    $originParametersUser.Add("Identity",$SAMAccountNAme) 
                    $originParametersUser.Add("Server","@uniqueParentCompany-alcoil.com")
                    $originParametersObject.Add("Server","@uniqueParentCompany-alcoil.com")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")    
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Office-Location-18"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","@uniqueParentCompanyacs.cn")   
                    $originParametersObject.Add("Server","@uniqueParentCompanyacs.cn")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")  
                    
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Company-Name-10"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = "US-MN-VS-DC01"
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","@uniqueParentCompanymn.com")    
                    $originParametersObject.Add("Server","@uniqueParentCompanymn.com")  
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Company-Name-11"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","@uniqueParentCompanylmp.ca")  
                    $originParametersObject.Add("Server","@uniqueParentCompanylmp.ca")   
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Office-Location-21"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","@uniqueParentCompanyselect.com")
                    $originParametersObject.Add("Server","@uniqueParentCompanyselect.com")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")   
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Company-Name-8"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "$origCred"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","@uniqueParentCompany.de")
                    $originParametersObject.Add("Server","@uniqueParentCompany.de")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")        
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Company-Name-17"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "anonSubsidiary-1-Hybrid-Worker"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","@anonSubsidiary-1.com")
                    $originParametersObject.Add("Server","@anonSubsidiary-1.com")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")    
                 }
                 $false {
                    $null
                }
            }
        }
        "unique-Company-Name-16"{
            switch ($refUserSynching) {
                $true {
                    $currentUserID = $jiraUserToModify
                    $originHybridWorkerGroup = $null
                    $originHybridWorkerCred = "anonSubsidiary-1-Hybrid-Worker"
                    $originParametersUser.Add("Identity",$SAMAccountNAme)
                    $originParametersUser.Add("Server","@anonSubsidiary-1.com")
                    $originParametersObject.Add("Server","@anonSubsidiary-1.com")
                    $originParametersObject.Add("TargetPath","$OriginLocationNonSyncOU")     
                 }
                 $false {
                    $null
                }
            }
        }
        Default {Write-Output "There is no matching location."}
    }
    #For Specific Variables at the new AD they will be created on
    switch ($newOfficeLocation) {
        "unique-Office-Location-0"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup  = "US-AZ-VS-DC01"
                    $destinationHybridWorkerCred   = "Testing-TT-Credential"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","uniqueParentCompany.COM")
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","14107562600")
                    $destinationGraphParameters.Add("UsageLocation","US")
    
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","14107562600")
                    $destinationGraphParameters.Add("UsageLocation","US")
                    $upnSuffix = "@uniqueParentCompany.com"
                }
            }
        }
        "unique-Office-Location-1"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = "US-CA-VS-DC01"
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","uniqueParentCompanyWest.COM")
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanywest.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","15596732207")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanywest.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","15596732207")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Office-Location-2"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","uniqueParentCompanyMW.COM")
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanymw.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","12179233431")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanymw.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","12179233431")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Office-Location-3"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","uniqueParentCompanyIA.COM") 
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanyia.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","17126573223")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanyia.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","17126573223")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Company-Name-20"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "anonSubsidiary-1-Hybrid-Worker"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","anonSubsidiary-1CORP.COM")  
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1corp.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","19797780095")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1corp.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","19797780095")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Company-Name-7"{
            switch ($shopOrOffice) {
                "Office" { 
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","uniqueParentCompany.BE")
                    $destinationLADExtensionAttributes.Add("co","Belgium")
                    $destinationLADExtensionAttributes.Add("countryCode","056")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.be"
                    $destinationGraphParameters.Add("Country","BE")
                    $destinationGraphParameters.Add("BusinessPhones","3212395029")
                    $destinationGraphParameters.Add("UsageLocation","BE")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.be"
                    $destinationGraphParameters.Add("Country","BE")
                    $destinationGraphParameters.Add("BusinessPhones","3212395029")
                    $destinationGraphParameters.Add("UsageLocation","BE")
                }
            }
        }
        "unique-Office-Location-6"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","uniqueParentCompany.IT")
                    $destinationLADExtensionAttributes.Add("co","Italy")
                    $destinationLADExtensionAttributes.Add("countryCode","380")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.it"
                    $destinationGraphParameters.Add("Country","IT")
                    $destinationGraphParameters.Add("BusinessPhones","39029399041")
                    $destinationGraphParameters.Add("UsageLocation","IT")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.it"
                    $destinationGraphParameters.Add("Country","IT")
                    $destinationGraphParameters.Add("BusinessPhones","39029399041")
                    $destinationGraphParameters.Add("UsageLocation","IT")
                }
            }
        }
        "uniqueParentCompany (Sondrio) Europe, S.rl.l."{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","uniqueParentCompany.IT") 
                    $destinationLADExtensionAttributes.Add("co","Italy")
                    $destinationLADExtensionAttributes.Add("countryCode","380")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.it"
                    $destinationGraphParameters.Add("Country","IT")
                    $destinationGraphParameters.Add("BusinessPhones","39029399041")
                    $destinationGraphParameters.Add("UsageLocation","IT")
                    
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.it"
                    $destinationGraphParameters.Add("Country","IT")
                    $destinationGraphParameters.Add("BusinessPhones","39029399041")
                    $destinationGraphParameters.Add("UsageLocation","IT")
                }
            }
        }
        "unique-Office-Location-8"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","uniqueParentCompanyCHINA.com")
                    $destinationLADExtensionAttributes.Add("co","CN")
                    $destinationLADExtensionAttributes.Add("countryCode","156")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanychina.com"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.61E+11")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanychina.com"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.61E+11")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                }
            }
        }
        "unique-Office-Location-9"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","uniqueParentCompanyCHINA.com")
                    $destinationLADExtensionAttributes.Add("co","CN")
                    $destinationLADExtensionAttributes.Add("countryCode","156")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanychina.com"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.62E+11")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanychina.com"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.62E+11")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                }
            }
        }
        "unique-Company-Name-3"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","uniqueParentCompany.com.au") 
                    $destinationLADExtensionAttributes.Add("co","AU")
                    $destinationLADExtensionAttributes.Add("countryCode","036")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.com.au"
                    $destinationGraphParameters.Add("Country","AU")
                    $destinationGraphParameters.Add("BusinessPhones","6.10E+11")
                    $destinationGraphParameters.Add("UsageLocation","AU")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.com.au"
                    $destinationGraphParameters.Add("Country","AU")
                    $destinationGraphParameters.Add("BusinessPhones","6.10E+11")
                    $destinationGraphParameters.Add("UsageLocation","AU")
                }
            }
        }
        "unique-Company-Name-18"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "anonSubsidiary-1-Hybrid-Worker"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","anonSubsidiary-1.com") 
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","19133225165")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","19133225165")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Company-Name-5"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "DryCooling-Hybrid-Worker"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","uniqueParentCompanyDC.com") 
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanydc.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","19083792665")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanydc.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","19083792665")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Company-Name-21"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = "US-NC-VS-DC01"
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","@towercomponentsinc.com") 
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@towercomponentsinc.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","13368242102")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@towercomponentsinc.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","13368242102")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Office-Location-27"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","uniqueParentCompanyMW.com")  
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanymw.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","16187833433")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanymw.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","16187833433")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Company-Name-6"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","uniqueParentCompany.DK")  
                    $destinationLADExtensionAttributes.Add("co","Denmark")
                    $destinationLADExtensionAttributes.Add("countryCode","208")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.dk"
                    $destinationGraphParameters.Add("Country","DK")
                    $destinationGraphParameters.Add("BusinessPhones","14598244999")
                    $destinationGraphParameters.Add("UsageLocation","DK")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.dk"
                    $destinationGraphParameters.Add("Country","DK")
                    $destinationGraphParameters.Add("BusinessPhones","14598244999")
                    $destinationGraphParameters.Add("UsageLocation","DK")
                }
            }
        }
        "unique-Company-Name-4"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","uniqueParentCompany.com.br")  
                    $destinationLADExtensionAttributes.Add("co","Brazil")
                    $destinationLADExtensionAttributes.Add("countryCode","076")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.com.br"
                    $destinationGraphParameters.Add("Country","BR")
                    $destinationGraphParameters.Add("BusinessPhones","1.55E+12")
                    $destinationGraphParameters.Add("UsageLocation","BR")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.com.br"
                    $destinationGraphParameters.Add("Country","BR")
                    $destinationGraphParameters.Add("BusinessPhones","1.55E+12")
                    $destinationGraphParameters.Add("UsageLocation","BR")
                }
            }
        }
        "unique-Office-Location-16"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","anonSubsidiary-1.com")  
                    $destinationLADExtensionAttributes.Add("co","Brazil")
                    $destinationLADExtensionAttributes.Add("countryCode","076")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","BR")
                    $destinationGraphParameters.Add("BusinessPhones","1.55E+12")
                    $destinationGraphParameters.Add("UsageLocation","BR")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","BR")
                    $destinationGraphParameters.Add("BusinessPhones","1.55E+12")
                    $destinationGraphParameters.Add("UsageLocation","BR")
                }
            }
        }
        "unique-Company-Name-2"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "Alcoil-Hybrid-Worker"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme) 
                    $destinationLADParameters.Add("Server","@uniqueParentCompany-alcoil.com")   
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany-alcoil.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","17173477500")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany-alcoil.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","17173477500")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Office-Location-18"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","@uniqueParentCompanyacs.cn")   
                    $destinationLADExtensionAttributes.Add("co","China")
                    $destinationLADExtensionAttributes.Add("countryCode","156")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanyacs.cn"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.66E+12")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanyacs.cn"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.66E+12")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                }
            }
        }
        "unique-Company-Name-10"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = "US-MN-VS-DC01"
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","@uniqueParentCompanymn.com")    
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanymn.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","15074468005")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanymn.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","15074468005")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Company-Name-11"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","@uniqueParentCompanylmp.ca")  
                    $destinationLADExtensionAttributes.Add("co","Canada")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanylmp.ca"
                    $destinationGraphParameters.Add("Country","CA")
                    $destinationGraphParameters.Add("BusinessPhones","14506299864")
                    $destinationGraphParameters.Add("UsageLocation","CA")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanylmp.ca"
                    $destinationGraphParameters.Add("Country","CA")
                    $destinationGraphParameters.Add("BusinessPhones","14506299864")
                    $destinationGraphParameters.Add("UsageLocation","CA")
                }
            }
        }
        "unique-Office-Location-21"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","@uniqueParentCompanyselect.com")   
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanyselect.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","18447859506")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanyselect.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","18447859506")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Company-Name-8"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "$destCred"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","@uniqueParentCompany.de")     
                    $destinationLADExtensionAttributes.Add("co","Germany")
                    $destinationLADExtensionAttributes.Add("countryCode","276")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.de"
                    $destinationGraphParameters.Add("Country","DE")
                    $destinationGraphParameters.Add("BusinessPhones","49215969560")
                    $destinationGraphParameters.Add("UsageLocation","DE")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.de"
                    $destinationGraphParameters.Add("Country","DE")
                    $destinationGraphParameters.Add("BusinessPhones","49215969560")
                    $destinationGraphParameters.Add("UsageLocation","DE")
                }
            }
        }
        "unique-Company-Name-17"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "anonSubsidiary-1-Hybrid-Worker"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","@anonSubsidiary-1.com")    
                    $destinationLADExtensionAttributes.Add("co","Malaysia")
                    $destinationLADExtensionAttributes.Add("countryCode","458")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","MY")
                    $destinationGraphParameters.Add("BusinessPhones","60380707255")
                    $destinationGraphParameters.Add("UsageLocation","MY")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","MY")
                    $destinationGraphParameters.Add("BusinessPhones","60380707255")
                    $destinationGraphParameters.Add("UsageLocation","MY")
                }
            }
        }
        "unique-Company-Name-16"{
            switch ($shopOrOffice) {
                "Office" {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerCred   = "anonSubsidiary-1-Hybrid-Worker"
                    $destinationLADParameters.Add("Identity",$SAMAccountNAme)
                    $destinationLADParameters.Add("Server","@anonSubsidiary-1.com")    
                    $destinationLADExtensionAttributes.Add("co","China")
                    $destinationLADExtensionAttributes.Add("countryCode","156")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.62E+11")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.62E+11")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                }
            }
        }
        Default {Write-Output "There is no matching location."}
    }
    <#
    #To Handle Shop/Office Transfers
    switch ($originLocation) {
        "unique-Office-Location-0"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup  = "US-AZ-VS-DC01"
                    $destinationHybridWorkerUser = "David.DrosdickAdmin@uniqueParentCompany.com"
                    $destinationHybridWorkerKeyVault = "TTWorker"
                    
                    $destinationLADParameters.Add("Server","uniqueParentCompany.COM")
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","14107562600")
                    $destinationGraphParameters.Add("UsageLocation","US")
    
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","14107562600")
                    $destinationGraphParameters.Add("UsageLocation","US")
                    $upnSuffix = "@uniqueParentCompany.com"
                }
            }
        }
        "unique-Office-Location-1"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = "US-CA-VS-DC01"
                    $destinationHybridWorkerUser = "uniqueParentCompanyadmin@uniqueParentCompany-West.uniqueParentCompanyW.com"
                    $destinationHybridWorkerKeyVault = "US-CA-VS-DC01"
                    
                    $destinationLADParameters.Add("Server","uniqueParentCompanyWest.COM")
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanywest.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","15596732207")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanywest.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","15596732207")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Office-Location-2"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","uniqueParentCompanyMW.COM")
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanymw.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","12179233431")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanymw.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","12179233431")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Office-Location-3"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","uniqueParentCompanyIA.COM") 
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanyia.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","17126573223")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanyia.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","17126573223")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Company-Name-20"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","anonSubsidiary-1CORP.COM")  
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1corp.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","19797780095")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1corp.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","19797780095")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Company-Name-7"{
            switch ($shopOrOffice) {
                Default { 
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","uniqueParentCompany.BE")
                    $destinationLADExtensionAttributes.Add("co","Belgium")
                    $destinationLADExtensionAttributes.Add("countryCode","056")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.be"
                    $destinationGraphParameters.Add("Country","BE")
                    $destinationGraphParameters.Add("BusinessPhones","3212395029")
                    $destinationGraphParameters.Add("UsageLocation","BE")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.be"
                    $destinationGraphParameters.Add("Country","BE")
                    $destinationGraphParameters.Add("BusinessPhones","3212395029")
                    $destinationGraphParameters.Add("UsageLocation","BE")
                }
            }
        }
        "unique-Office-Location-6"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","uniqueParentCompany.IT")
                    $destinationLADExtensionAttributes.Add("co","Italy")
                    $destinationLADExtensionAttributes.Add("countryCode","380")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.it"
                    $destinationGraphParameters.Add("Country","IT")
                    $destinationGraphParameters.Add("BusinessPhones","39029399041")
                    $destinationGraphParameters.Add("UsageLocation","IT")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.it"
                    $destinationGraphParameters.Add("Country","IT")
                    $destinationGraphParameters.Add("BusinessPhones","39029399041")
                    $destinationGraphParameters.Add("UsageLocation","IT")
                }
            }
        }
        "uniqueParentCompany (Sondrio) Europe, S.rl.l."{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","uniqueParentCompany.IT") 
                    $destinationLADExtensionAttributes.Add("co","Italy")
                    $destinationLADExtensionAttributes.Add("countryCode","380")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.it"
                    $destinationGraphParameters.Add("Country","IT")
                    $destinationGraphParameters.Add("BusinessPhones","39029399041")
                    $destinationGraphParameters.Add("UsageLocation","IT")
                    
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.it"
                    $destinationGraphParameters.Add("Country","IT")
                    $destinationGraphParameters.Add("BusinessPhones","39029399041")
                    $destinationGraphParameters.Add("UsageLocation","IT")
                }
            }
        }
        "unique-Office-Location-8"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","uniqueParentCompanyCHINA.com")
                    $destinationLADExtensionAttributes.Add("co","CN")
                    $destinationLADExtensionAttributes.Add("countryCode","156")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanychina.com"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.61E+11")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanychina.com"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.61E+11")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                }
            }
        }
        "unique-Office-Location-9"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","uniqueParentCompanyCHINA.com")
                    $destinationLADExtensionAttributes.Add("co","CN")
                    $destinationLADExtensionAttributes.Add("countryCode","156")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanychina.com"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.62E+11")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanychina.com"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.62E+11")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                }
            }
        }
        "unique-Company-Name-3"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","uniqueParentCompany.com.au") 
                    $destinationLADExtensionAttributes.Add("co","AU")
                    $destinationLADExtensionAttributes.Add("countryCode","036")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.com.au"
                    $destinationGraphParameters.Add("Country","AU")
                    $destinationGraphParameters.Add("BusinessPhones","6.10E+11")
                    $destinationGraphParameters.Add("UsageLocation","AU")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.com.au"
                    $destinationGraphParameters.Add("Country","AU")
                    $destinationGraphParameters.Add("BusinessPhones","6.10E+11")
                    $destinationGraphParameters.Add("UsageLocation","AU")
                }
            }
        }
        "unique-Company-Name-18"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","anonSubsidiary-1.com") 
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","19133225165")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","19133225165")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Company-Name-5"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","uniqueParentCompanyDC.com") 
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanydc.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","19083792665")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanydc.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","19083792665")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Company-Name-21"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = "US-NC-VS-DC01"
                    $destinationHybridWorkerUser = "uniqueParentCompanyadmin@towercomponentsinc.com"
                    $destinationHybridWorkerKeyVault = "US-NC-VS-DC01"
                    
                    $destinationLADParameters.Add("Server","@towercomponentsinc.com") 
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@towercomponentsinc.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","13368242102")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@towercomponentsinc.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","13368242102")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Office-Location-27"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","uniqueParentCompanyMW.com")  
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanymw.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","16187833433")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanymw.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","16187833433")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Company-Name-6"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","uniqueParentCompany.DK")  
                    $destinationLADExtensionAttributes.Add("co","Denmark")
                    $destinationLADExtensionAttributes.Add("countryCode","208")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.dk"
                    $destinationGraphParameters.Add("Country","DK")
                    $destinationGraphParameters.Add("BusinessPhones","14598244999")
                    $destinationGraphParameters.Add("UsageLocation","DK")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.dk"
                    $destinationGraphParameters.Add("Country","DK")
                    $destinationGraphParameters.Add("BusinessPhones","14598244999")
                    $destinationGraphParameters.Add("UsageLocation","DK")
                }
            }
        }
        "unique-Company-Name-4"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","uniqueParentCompany.com.br")  
                    $destinationLADExtensionAttributes.Add("co","Brazil")
                    $destinationLADExtensionAttributes.Add("countryCode","076")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.com.br"
                    $destinationGraphParameters.Add("Country","BR")
                    $destinationGraphParameters.Add("BusinessPhones","1.55E+12")
                    $destinationGraphParameters.Add("UsageLocation","BR")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.com.br"
                    $destinationGraphParameters.Add("Country","BR")
                    $destinationGraphParameters.Add("BusinessPhones","1.55E+12")
                    $destinationGraphParameters.Add("UsageLocation","BR")
                }
            }
        }
        "unique-Office-Location-16"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","anonSubsidiary-1.com")  
                    $destinationLADExtensionAttributes.Add("co","Brazil")
                    $destinationLADExtensionAttributes.Add("countryCode","076")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","BR")
                    $destinationGraphParameters.Add("BusinessPhones","1.55E+12")
                    $destinationGraphParameters.Add("UsageLocation","BR")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","BR")
                    $destinationGraphParameters.Add("BusinessPhones","1.55E+12")
                    $destinationGraphParameters.Add("UsageLocation","BR")
                }
            }
        }
        "unique-Company-Name-2"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                     
                    $destinationLADParameters.Add("Server","@uniqueParentCompany-alcoil.com")   
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany-alcoil.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","17173477500")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany-alcoil.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","17173477500")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Office-Location-18"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","@uniqueParentCompanyacs.cn")   
                    $destinationLADExtensionAttributes.Add("co","China")
                    $destinationLADExtensionAttributes.Add("countryCode","156")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanyacs.cn"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.66E+12")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanyacs.cn"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.66E+12")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                }
            }
        }
        "unique-Company-Name-10"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = "US-MN-VS-DC01"
                    $destinationHybridWorkerUser = "uniqueParentCompanyadmin@uniqueParentCompany.mn"
                    $destinationHybridWorkerKeyVault = "US-MN-VS-DC01"
                    
                    $destinationLADParameters.Add("Server","@uniqueParentCompanymn.com")    
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanymn.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","15074468005")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanymn.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","15074468005")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Company-Name-11"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","@uniqueParentCompanylmp.ca")  
                    $destinationLADExtensionAttributes.Add("co","Canada")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanylmp.ca"
                    $destinationGraphParameters.Add("Country","CA")
                    $destinationGraphParameters.Add("BusinessPhones","14506299864")
                    $destinationGraphParameters.Add("UsageLocation","CA")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanylmp.ca"
                    $destinationGraphParameters.Add("Country","CA")
                    $destinationGraphParameters.Add("BusinessPhones","14506299864")
                    $destinationGraphParameters.Add("UsageLocation","CA")
                }
            }
        }
        "unique-Office-Location-21"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","@uniqueParentCompanyselect.com")   
                    $destinationLADExtensionAttributes.Add("co","United States")
                    $destinationLADExtensionAttributes.Add("countryCode","840")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanyselect.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","18447859506")
                    $destinationGraphParameters.Add("UsageLocation","US")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompanyselect.com"
                    $destinationGraphParameters.Add("Country","US")
                    $destinationGraphParameters.Add("BusinessPhones","18447859506")
                    $destinationGraphParameters.Add("UsageLocation","US")
                }
            }
        }
        "unique-Company-Name-8"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","@uniqueParentCompany.de")     
                    $destinationLADExtensionAttributes.Add("co","Germany")
                    $destinationLADExtensionAttributes.Add("countryCode","276")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.de"
                    $destinationGraphParameters.Add("Country","DE")
                    $destinationGraphParameters.Add("BusinessPhones","49215969560")
                    $destinationGraphParameters.Add("UsageLocation","DE")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@uniqueParentCompany.de"
                    $destinationGraphParameters.Add("Country","DE")
                    $destinationGraphParameters.Add("BusinessPhones","49215969560")
                    $destinationGraphParameters.Add("UsageLocation","DE")
                }
            }
        }
        "unique-Company-Name-17"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","@anonSubsidiary-1.com")    
                    $destinationLADExtensionAttributes.Add("co","Malaysia")
                    $destinationLADExtensionAttributes.Add("countryCode","458")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","MY")
                    $destinationGraphParameters.Add("BusinessPhones","60380707255")
                    $destinationGraphParameters.Add("UsageLocation","MY")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","MY")
                    $destinationGraphParameters.Add("BusinessPhones","60380707255")
                    $destinationGraphParameters.Add("UsageLocation","MY")
                }
            }
        }
        "unique-Company-Name-16"{
            switch ($shopOrOffice) {
                Default {
                    $currentUserID = $jiraUserToModify
                    $destinationHybridWorkerGroup = $null
                    $destinationHybridWorkerUser = $null
                    $destinationHybridWorkerKeyVault = $null
                    
                    $destinationLADParameters.Add("Server","@anonSubsidiary-1.com")    
                    $destinationLADExtensionAttributes.Add("co","China")
                    $destinationLADExtensionAttributes.Add("countryCode","156")
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.62E+11")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                 }
                "Shop" {
                    $destinationGraphParameters.Add("UserID",$jiraUserToModify)
                    $upnSuffix = "@anonSubsidiary-1.com"
                    $destinationGraphParameters.Add("Country","CN")
                    $destinationGraphParameters.Add("BusinessPhones","8.62E+11")
                    $destinationGraphParameters.Add("UsageLocation","CN")
                }
            }
        }
        Default {Write-Output "There is no matching location."}
    }#>
    #Pull their Graph User Attributes
    if (($newSupervisor -ne "") -and ($null -ne $newSupervisor)){
        $managerSync = (Get-MgBetaUser -userid $newSupervisor | Select-Object -Property OnPremisesDomainName).OnPremisesDomainName

    }


    Write-Output "The following values will be modified:"
    if ($newCompany -ne $($referenceUser.CompanyName) -and ($newCompany -ne "")-and ($null -ne $newCompany)){
        Write-Output "New Company:          $newCompany"
        $destinationGraphParameters.Add("CompanyName","$newCompany")
  
    }

    if ($newOfficeLocation -ne $($referenceUser.OfficeLocation) -and ($newOfficeLocation -ne "")-and ($null -ne $newOfficeLocation)){
        Write-Output "New Office Location:  $newOfficeLocation"
        $destinationGraphParameters.Add("OfficeLocation","$newOfficeLocation")

    }

    If ($newDepartment -ne $($referenceUser.Department) -and ($newDepartment -ne '') -and ($null -ne $newDepartment)){
        Write-Output "New Department:       $newDepartment"
        $destinationGraphParameters.add("Department","$newDepartment")
    }

    If ($newJobTitle -ne $($referenceUser.JobTitle) -and ($newJobTitle -ne '') -and ($null -ne $newJobTitle)){
        Write-Output "New Job Title:        $newJobTitle"
        $destinationGraphParameters.Add("JobTitle","$newJobTitle")

    }


    If (($newSupervisor -ne $manager) -and ($newSupervisor -ne "") -and ($null -ne $newSupervisor)){
        switch ($refUserSynching) {
            $true {
                if ($isTransfer -eq "No"){
                    If ($managerSync -eq $referenceUser.OnPremisesDomainName){
                        Write-Output "Supervisor:           $newSupervisor"
                        $newManagerUPN = $newSupervisor
                    }
                    Else{
                        Write-Output "Manager is not supported in this case as they are synching from different domains"
                    }
                }
                else{
                    If ($managerSync -eq $referenceUser.OnPremisesDomainName){
                        Write-Output "Manager is not supported in this case as they are synching from different domains"
                    }
                    Else{    
                        Write-Output "Supervisor:           $newSupervisor"
                        $newManagerUPN = $newSupervisor
                    }
                    
                }
            }
            $false {
                    $newManagerUPN = $newSupervisor
            }
    }
    }

    If ($newFirstName -ne $($referenceUser.GivenName) -and ($newFirstName -ne "") -and ($null -ne $newFirstName)){
        $newFormattedFirstName = Format-Name -inputName $newFirstName
        Write-Output "New FirstName:        $newFormattedFirstName"
        $destinationGraphParameters.Add("GivenName","$newFormattedFirstName")
    }
    else{
        $newFormattedFirstName = Format-Name -InputName $referenceUser.GivenName
        Write-Output "New FirstName:        $newFormattedFirstName"
        $destinationGraphParameters.Add("GivenName","$newFormattedFirstName")
    }

    If ($newSurName -ne $($referenceUser.Surname) -and ($newSurName -ne "") -and ($null -ne $newSurName)){
        $newFormattedLastName = Format-Name -inputName $newSurName
        Write-Output "New LastName:         $newFormattedLastName"
        $destinationGraphParameters.add("Surname","$newFormattedLastName")
    }
    else{
        $newFormattedLastName = Format-Name -InputName $referenceUser.Surname
        Write-Output "New LastName:         $newFormattedLastName"
        $destinationGraphParameters.add("Surname","$newFormattedLastName")
    }
    if ($shopOrOffice -ne $($referenceUser.OnPremisesExtensionAttributes.ExtensionAttribute1) -and ($shopOrOffice -ne "")-and ($null -ne $shopOrOffice)){
        Write-Output "New Work Location:  $shopOrOffice"
        $destinationGraphParameters.Add("ExtensionAttribute1","$shopOrOffice")
    }
    if ($officeAppBitType -ne $($referenceUser.OnPremisesExtensionAttributes.ExtensionAttribute3)){
        if ($officeAppBitType -eq "32"){
            if(($referenceUser.OnPremisesExtensionAttributes.ExtensionAttribute3 -ne "") -and ($null -ne $referenceUser.OnPremisesExtensionAttributes.ExtensionAttribute3)){
                Write-Output "$($referenceUser.DisplayName) requires a modification to their Office Apps"
                $destinationGraphParameters.add("ExtensionAttribute3",$null)
            }
            Else{
                Write-Output "$($referenceUser.DisplayName) does not require a modification to their Office Apps"

            }
        }
        Else{
            $destinationGraphParameters.Add("ExtensionAttribute3","$officeAppBitType")
        }
    }
    $newUPN = $destinationGraphParameters.givenname , "." , $destinationGraphParameters.surname , $upnSuffix -join ""
    $destinationGraphParameters.Remove("UserPrincipalName")
    $destinationGraphParameters.Add("UserPrincipalName",$newUPN)
    If ($refUserSynching){
        Write-Output "I am on line 2286, this is a user who is synching."
        Write-Output "`n`SAMAccountName: $SAMAccountName"
        Write-Output "Origin Hybrid Worker Runbook: $originRunbook"
        Write-Output "Origin User Synching Status: $originUserSynching"
        Write-Output "Origin Hybrid Worker Group Performing this Operation: $originHybridWorkerGroup"
        Write-Output "Origin Hybrid Worker Credential Object: $originHybridWorkerCred"
        Write-Output "Origin Parameters from the Ticket for the User:"
        $originParametersUser | Format-Table 
        Write-Output "Origin Parameters from the Ticket for the User as an AD Object:"
        $originParametersObjectv2 = @{}
        # Iterate through each key-value pair in the Ordered Dictionary
        foreach ($entry in $originParametersObject.Keys){
                $stringValue = ($originParametersObject[$entry]).Replace(",","~")
                $originParametersObjectv2.add("$entry","$stringValue") 
        }

        # Output the modified Ordered Dictionary
        $originParametersObject = $originPArametersObjectv2
        $originParametersObject | Format-Table
        Write-Output "NOTE: ',' have been replaced with '~' due to system issues with Runbooks. They are fixed on the Hybrid Worker."
        Write-Output "`n`n`nDestination Graph Parameters:"
        $destinationGraphParameters | Format-Table

        Write-Output "`n`n`Destination Hybrid Worker Runbook: $destinationRunbook"
        Write-Output "Destination Hybrid Worker Group Performing this Operation: $destinationHybridWorkerGroup"
        Write-Output "Destination Hybrid Worker Credential Object: $destinationHybridWorkerCred"
        Write-Output "Destination Local AD Parameters Ticket:"
        $destinationLADParameters | Format-Table 

        Write-Output "`n`Destination On Premises Extension Attributes:"
        $destinationLADExtensionAttributes | Format-Table

        
        #Starting the Origin Runbook
        if (($refUserSynching) -and ($null -ne $originHybridWorkerGroup)){
            Write-Output "I am on line 2323, this is a user who is synching and there are Hybrid Workers Configured to Modify the Origin Account."
            Write-Output "Executing: '$originRunbook'"  
            $originRunbookParameters = [ordered]@{"Key"="$key";"originParametersUser"=$originParametersUser;"originParametersObject"=$originParametersObject;"originHybridWorkerCred"="$originHybridWorkerCred";"currentUserID"="$currentUserID";"originSynching"=$originSynching}
            start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name $originRunbook -ResourceGroupName "uniqueParentCompanyGIT"  -RunOn $originHybridWorkerGroup -Parameters $originRunbookParameters -wait
            $restoreRunbookParameters = [ordered]@{"Key"="$key";"originGraphUserID"="$originGraphUserID"}
            Write-Output "Executing: 'User-Transfer-3-Restore'" 
            start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name "User-Transfer-3-Restore" -ResourceGroupName "uniqueParentCompanyGIT" -Parameters $restoreRunbookParameters -Wait
            $graphModRunbook = [ordered]@{"Key"="$key";"originUPN"="$jiraUserToModify";"ParamsFromTicket"=$destinationGraphParameters;"newManagerUPN" = $newManagerUPN; "newUPN" = "$newUPN";"isTransfer" = "$isTransfer"}
            Write-Output "Executing: 'User-Transfer-4-Modify-Entra-Account'" 
            start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name "User-Transfer-4-Modify-Entra-Account" -ResourceGroupName "uniqueParentCompanyGIT"  -Parameters $graphModRunbook -Wait
            if ($null -ne $destinationHybridWorkerGroup){
                $destinationRunbookParameters = [ordered]@{"Key"="$key";"destinationLADParameters"=$destinationLADParameters;"destinationHybridWorkerCred" = "$destinationHybridWorkerCred";"newUPN" = "$newUPN";"currentUserID" = "$originGraphUserID"}
                Write-Output "Executing: 'User-Transfer-5-Create-Local-From-Graph-72'"
                start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name "User-Transfer-5-Create-Local-From-Graph-72" -ResourceGroupName "uniqueParentCompanyGIT" -RunOn $destinationHybridWorkerGroup  -Parameters $destinationRunbookParameters -Wait
                Write-Output "Executing: 'Invoke-uniqueParentCompany-Sync'"
                start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name "Invoke-uniqueParentCompany-Sync" -ResourceGroupName "uniqueParentCompanyGIT" -RunOn "US-AZ-VS-DC01" -Wait
                $date = get-date
                $DoW = $date.DayOfWeek.ToString()
                $Month = (Get-date $date -format "MM").ToString()
                $Day = (Get-date $date -format "dd").ToString()
                $pw = $DoW+$Month+$Day+"!"
                Set-SuccessfulCommentRunbook -successMessage "$newUPN has been created on $($destinationLADPArameters.Server) with password '$pw', and this has been resolved by Automation!" -key $key -jiraHeader $jiraHeader
                exit 0
            }
            Else{
                Write-Output "I am on line 2343, this is a user who is synching but there are no Hybrid Workers Configured to Modify the Destination Account."  
                $publicErrorMEssage = "$newOfficeLocation is not configured for a Hybrid Worker Runbook. Their Local Account will need to be done manually"
                Set-PublicErrorJira -key $key -publicErrorMessage $publicErrorMEssage -jiraHeader $jiraHeader
                exit 0
            }
            exit 0
        }
        Else{
            Write-Output "I am on line 2351, this is a user who is synching but there are no Hybrid Workers Configured to Modify the Origin Account."  
            $publicErrorMEssage = "$originLocation is not configured for a Hybrid Worker Runbook. This will need to be done manually"
            Set-PublicErrorJira -key $key -publicErrorMessage $publicErrorMEssage -jiraHeader $jiraHeader
            exit 0
        }
    }
    Else{
        Write-Output "I am on line 2358, this is for a non-synching, Graph Only User"
        Write-Output "I would have changed the user on Graph here"
        Write-Output "UPN: $jiraUserToModify"
        Write-Output "Origin User Synching Status: $originUserSynching"
        Write-Output "Origin Hybrid Worker Group Performing this Operation: $originHybridWorkerGroup"
        Write-Output "Origin Hybrid Worker Credential Item: $originHybridWorkerCred"
        Write-Output "Origin Parameters from the Ticket:"
        $originParametersUser | Format-Table 

        Write-Output "`n`n`nDestination Hybrid Worker Group Performing this Operation: $destinationHybridWorkerGroup"
        Write-Output "Destination Hybrid Worker Credential Item: $destinationHybridWorkerCred"  
        Write-Output "Destination Parameters from the Ticket:"
        $destinationGraphParameters | Format-Table 

        Write-Output "`n`nExtension Attributes:"
        $destinationLADExtensionAttributes | Format-Table

        #Starting the Origin Runbook
        $graphModRunbook = [ordered]@{"Key"="$key";"originUPN"="$jiraUserToModify";"ParamsFromTicket"=$destinationGraphParameters;"newManagerUPN" = $newManagerUPN; "newUPN" = "$newUPN";"isTransfer" = "$isTransfer"}
        Write-Output "Executing: 'User-Transfer-4-Modify-Entra-Account'"
        start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name "User-Transfer-4-Modify-Entra-Account" -ResourceGroupName "uniqueParentCompanyGIT"  -Parameters $graphModRunbook -Wait
        if ($null -ne $destinationHybridWorkerGroup){
            $destinationRunbookParameters = [ordered]@{"Key"="$key";"destinationLADParameters"=$destinationLADParameters;"destinationHybridWorkerCred" = "$destinationHybridWorkerCred"; "newUPN" = "$newUPN";"currentUserID" = "$originGraphUserID"}
            Write-Output "Executing: 'User-Transfer-5-Create-Local-From-Graph-72'"
            start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name "User-Transfer-5-Create-Local-From-Graph-72" -ResourceGroupName "uniqueParentCompanyGIT" -RunOn $destinationHybridWorkerGroup  -Parameters $destinationRunbookParameters  -Wait
            Write-Output "Executing: 'Invoke-uniqueParentCompany-Sync'"
            start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name "Invoke-uniqueParentCompany-Sync" -ResourceGroupName "uniqueParentCompanyGIT" -RunOn "US-AZ-VS-DC01" -Wait        
            $date = get-date
            $DoW = $date.DayOfWeek.ToString()
            $Month = (Get-date $date -format "MM").ToString()
            $Day = (Get-date $date -format "dd").ToString()
            $pw = $DoW+$Month+$Day+"!"
            Set-SuccessfulCommentRunbook -successMessage "$newUPN has been created on $($destinationLADPArameters.Server) with password '$pw', and this has been resolved by Automation!" -key $key -jiraHeader $jiraHeader
            exit 0
        }
        Else{
            Write-Output "I am on line 2391 and a Hybrid Worker is either not configured, or required, for this."  
            $publicMessage = "User Update: $newUPN Successfully Completed! Their Local Account, if required, will need to be done manually."
            Set-SuccessfulCommentRunbook -successMessage $publicMessage -jiraHeader $jiraHeader -key $key
            exit 0
        }
        exit 0
    }
    
    }
    Default {Write-Output "This is a User Change"
        $newOfficeLocation  = $form.fields.customfield_10787.value
        $newDepartment      = $form.fields.customfield_10787.child.value
        $locationKey        = $referenceUser.OfficeLocation
            
        #Pull their Graph User Attributes
        if (($newSupervisor -ne "") -and ($null -ne $newSupervisor)){
            $managerSync = (Get-MgBetaUser -userid $newSupervisor | Select-Object -Property OnPremisesDomainName).OnPremisesDomainName
        
        }
        
        If ($referenceUser.OnPremisesSyncEnabled -eq $true){
            if ($null -ne $referenceUser.OnPremisesDomainName){
                Write-Output "User is Synching"
                Write-Output "User To Modify:       $jiraUserToModify"
                $samAccountName = $referenceUser.OnPremisesSAMAccountName
                $refUserSynching = $true
                $originSynching = $true
                $runbook = "User-Change-2-LocalAD-72"
            }
    
            else{
                Write-Output "User is Graph Only"
                Write-Output "User To Modify:       $jiraUserToModify"
                $runbook = "User-Change-2-Graph"  
                $refUserSynching = $false
                $originSynching = $false
            }
        }
        else{
            Write-Output "User is Graph Only"
            Write-Output "User To Modify:       $jiraUserToModify"
            $refUserSynching = $false
            $originSynching = $false
            $runbook = "User-Change-2-Graph"
        }
        
        
        
        
        Write-Output "The following values will be modified:"
        if ($newCompany -ne $($referenceUser.CompanyName) -and ($newCompany -ne "")-and ($null -ne $newCompany)){
            Write-Output "New Company:          $newCompany"
            switch ($refUserSynching) {
                $true {
                    $paramsFromTicket.add("Company","$newCompany")
                    
                }
                $false {
                    $paramsFromTicket.Add("CompanyName","$newCompany")
                }
            }
        }
        
        if ($newOfficeLocation -ne $($referenceUser.OfficeLocation) -and ($newOfficeLocation -ne "")-and ($null -ne $newOfficeLocation)){
            Write-Output "New Office Location:  $newOfficeLocation"
            switch ($refUserSynching) {
                $true {
                    $paramsFromTicket.add("Office","$newOfficeLocation")
                    
                }
                $false {
                    $paramsFromTicket.Add("OfficeLocation","$newOfficeLocation")
                }
            }
        }
        
        If ($newDepartment -ne $($referenceUser.Department) -and ($newDepartment -ne '') -and ($null -ne $newDepartment)){
            Write-Output "New Department:       $newDepartment"
            $paramsFromTicket.add("Department","$newDepartment")
        }
        
        If ($newJobTitle -ne $($referenceUser.JobTitle) -and ($newJobTitle -ne '') -and ($null -ne $newJobTitle)){
            Write-Output "New Job Title:        $newJobTitle"
            switch ($refUserSynching) {
                $true {
                    $paramsFromTicket.add("Title","$newJobTitle")
                    
                }
                $false {
                    $paramsFromTicket.Add("JobTitle","$newJobTitle")
                }
            }
        }
        
        
        If (($newSupervisor -ne $manager) -and ($newSupervisor -ne "") -and ($null -ne $newSupervisor)){
            switch ($refUserSynching) {
                $true {
                    if ($isTransfer -eq "No"){
                        If ($managerSync -eq $referenceUser.OnPremisesDomainName){
                            Write-Output "Supervisor:           $newSupervisor"
                            $newManagerUPN = $newSupervisor
                        }
                        Else{
                            Write-Output "Manager is not supported in this case as they are synching from different domains"
                        }
                    }
                    else{
                        If ($managerSync -eq $referenceUser.OnPremisesDomainName){
                            Write-Output "Manager is not supported in this case as they are synching from different domains"
                        }
                        Else{    
                            Write-Output "Supervisor:           $newSupervisor"
                            $newManagerUPN = $newSupervisor
                        }
                        
                    }
                }
                $false {
                        $newManagerUPN = $newSupervisor
                }
        }
        }
        
        If ($newFirstName -ne $($referenceUser.GivenName) -and ($newFirstName -ne "") -and ($null -ne $newFirstName)){
            $newFormattedFirstName = Format-Name -inputName $newFirstName
            Write-Output "New FirstName:        $newFormattedFirstName"
            $paramsFromTicket.Add("GivenName","$newFormattedFirstName")
        }
        
        If ($newSurName -ne $($referenceUser.Surname) -and ($newSurName -ne "") -and ($null -ne $newSurName)){
            $newFormattedLastName = Format-Name -inputName $newSurName
            Write-Output "New LastName:         $newFormattedLastName"
            $paramsFromTicket.add("Surname","$newFormattedLastName")
        }

        if (($null -ne $newFormattedFirstName) -or ($null -ne $newFormattedLastName)){
            $newDisplayName = $newFormattedFirstName , $newFormattedLastName -join " "
            if ($newDisplayName -cne $($referenceUser.DisplayName)){
                Write-Output "New DisplayName:  $newDisplayName"
                $paramsFromTicket.add("DisplayName","$newDisplayName")
            }
        }
        
        if ($shopOrOffice -ne $($referenceUser.OnPremisesExtensionAttributes.ExtensionAttribute1) -and ($shopOrOffice -ne "")-and ($null -ne $shopOrOffice)){
            Write-Output "New Work Location:  $shopOrOffice"
            switch ($refUserSynching) {
                $true {
                    $extensionAttributes.add("ExtensionAttribute1","$shopOrOffice")
                    
                }
                $false {
                    $paramsFromTicket.Add("ExtensionAttribute1","$shopOrOffice")
                }
            }
        }
        if ($officeAppBitType -ne $($referenceUser.OnPremisesExtensionAttributes.ExtensionAttribute3)){
            if ($officeAppBitType -eq "32"){
                if(($referenceUser.OnPremisesExtensionAttributes.ExtensionAttribute3 -ne "") -and ($null -ne $referenceUser.OnPremisesExtensionAttributes.ExtensionAttribute3)){
                    Write-Output "$($referenceUser.DisplayName) requires a modification to their Office Apps"
                    switch ($refUserSynching) {
                        $true {
                            $extensionAttributes.add("ExtensionAttribute3",$null)
                            
                        }
                        $false {
                            $paramsFromTicket.Add("ExtensionAttribute3",$null)
                        }
                    }
                }
                Else{
                    Write-Output "$($referenceUser.DisplayName) does not require a modification to their Office Apps"
    
                }
            }
            Else{
                Write-Output "New Office App Configuration:  $officeAppBitType"
                switch ($refUserSynching) {
                    $true {
                        $extensionAttributes.add("ExtensionAttribute3","$officeAppBitType")
                        
                    }
                    $false {
                        $paramsFromTicket.Add("ExtensionAttribute3","$officeAppBitType")
                    }
                }
            }
        }
        
        switch ($locationKey) {
            "unique-Office-Location-0"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup  = "US-AZ-VS-DC01"
                        $hybridWorkerCred = "Testing-TT-Credential"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","uniqueParentCompany.COM")
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("OfficePhone","14107562600")
                        $extensionAttributes.Add("co","United States")
                        $extensionAttributes.Add("countryCode","840")
        
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("BusinessPhones","14107562600")
                        $paramsFromTicket.Add("UsageLocation","US")
                    }
                }
            }
            "unique-Office-Location-1"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = "US-CA-VS-DC01"
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","uniqueParentCompanyWest.COM")
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("OfficePhone","15596732207")
                        $extensionAttributes.Add("co","United States")
                        $extensionAttributes.Add("countryCode","840")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("BusinessPhones","15596732207")
                        $paramsFromTicket.Add("UsageLocation","US")
                    }
                }
            }
            "unique-Office-Location-2"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","uniqueParentCompanyMW.COM")
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("OfficePhone","12179233431")
                        $extensionAttributes.Add("co","United States")
                        $extensionAttributes.Add("countryCode","840")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("BusinessPhones","12179233431")
                        $paramsFromTicket.Add("UsageLocation","US")
                    }
                }
            }
            "unique-Office-Location-3"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","uniqueParentCompanyIA.COM") 
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("OfficePhone","17126573223")
                        $extensionAttributes.Add("co","United States")
                        $extensionAttributes.Add("countryCode","840")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("BusinessPhones","17126573223")
                        $paramsFromTicket.Add("UsageLocation","US")
                    }
                }
            }
            "unique-Company-Name-20"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "anonSubsidiary-1-Hybrid-Worker"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","anonSubsidiary-1CORP.COM")  
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("OfficePhone","19797780095")
                        $extensionAttributes.Add("co","United States")
                        $extensionAttributes.Add("countryCode","840")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("BusinessPhones","19797780095")
                        $paramsFromTicket.Add("UsageLocation","US")
                    }
                }
            }
            "unique-Company-Name-7"{
                switch ($refUserSynching) {
                    $true { 
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","uniqueParentCompany.BE")
                        $paramsFromTicket.Add("Country","BE")
                        $paramsFromTicket.Add("OfficePhone","3212395029")
                        $extensionAttributes.Add("co","Belgium")
                        $extensionAttributes.Add("countryCode","056")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","BE")
                        $paramsFromTicket.Add("BusinessPhones","3212395029")
                        $paramsFromTicket.Add("UsageLocation","BE")
                    }
                }
            }
            "unique-Office-Location-6"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","uniqueParentCompany.IT")
                        $paramsFromTicket.Add("Country","IT")
                        $paramsFromTicket.Add("OfficePhone","39029399041")
                        $extensionAttributes.Add("co","Italy")
                        $extensionAttributes.Add("countryCode","380")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","IT")
                        $paramsFromTicket.Add("BusinessPhones","39029399041")
                        $paramsFromTicket.Add("UsageLocation","IT")
                    }
                }
            }
            "uniqueParentCompany (Sondrio) Europe, S.rl.l."{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","uniqueParentCompany.IT") 
                        $paramsFromTicket.Add("Country","IT")
                        $paramsFromTicket.Add("OfficePhone","39029399041")
                        $extensionAttributes.Add("co","Italy")
                        $extensionAttributes.Add("countryCode","380")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","IT")
                        $paramsFromTicket.Add("BusinessPhones","39029399041")
                        $paramsFromTicket.Add("UsageLocation","IT")
                    }
                }
            }
            "unique-Office-Location-8"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","uniqueParentCompanyCHINA.com")
                        $paramsFromTicket.Add("Country","CN")
                        $paramsFromTicket.Add("OfficePhone","8.61E+11")
                        $extensionAttributes.Add("co","CN")
                        $extensionAttributes.Add("countryCode","156")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","CN")
                        $paramsFromTicket.Add("BusinessPhones","8.61E+11")
                        $paramsFromTicket.Add("UsageLocation","CN")
                    }
                }
            }
            "unique-Office-Location-9"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                       $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","uniqueParentCompanyCHINA.com")
                        $paramsFromTicket.Add("Country","CN")
                        $paramsFromTicket.Add("OfficePhone","8.62E+11")
                        $extensionAttributes.Add("co","CN")
                        $extensionAttributes.Add("countryCode","156")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","CN")
                        $paramsFromTicket.Add("BusinessPhones","8.62E+11")
                        $paramsFromTicket.Add("UsageLocation","CN")
                    }
                }
            }
            "unique-Company-Name-3"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","uniqueParentCompany.com.au") 
                        $paramsFromTicket.Add("Country","AU")
                        $paramsFromTicket.Add("OfficePhone","6.10E+11")
                        $extensionAttributes.Add("co","AU")
                        $extensionAttributes.Add("countryCode","036")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","AU")
                        $paramsFromTicket.Add("BusinessPhones","6.10E+11")
                        $paramsFromTicket.Add("UsageLocation","AU")
                    }
                }
            }
            "unique-Company-Name-18"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "anonSubsidiary-1-Hybrid-Worker"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","anonSubsidiary-1.com") 
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("OfficePhone","19133225165")
                        $extensionAttributes.Add("co","United States")
                        $extensionAttributes.Add("countryCode","840")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("BusinessPhones","19133225165")
                        $paramsFromTicket.Add("UsageLocation","US")
                    }
                }
            }
            "unique-Company-Name-5"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "DryCooling-Hybrid-Worker"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","uniqueParentCompanyDC.com") 
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("OfficePhone","19083792665")
                        $extensionAttributes.Add("co","United States")
                        $extensionAttributes.Add("countryCode","840")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("BusinessPhones","19083792665")
                        $paramsFromTicket.Add("UsageLocation","US")
                    }
                }
            }
            "unique-Company-Name-21"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = "US-NC-VS-DC01"
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("Server","@towercomponentsinc.com") 
                        $paramsFromTicket.Add("OfficePhone","13368242102")
                        $extensionAttributes.Add("co","United States")
                        $extensionAttributes.Add("countryCode","840")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("BusinessPhones","13368242102")
                        $paramsFromTicket.Add("UsageLocation","US")
                    }
                }
            }
            "unique-Office-Location-27"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","uniqueParentCompanyMW.com")  
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("OfficePhone","16187833433")
                        $extensionAttributes.Add("co","United States")
                        $extensionAttributes.Add("countryCode","840")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("BusinessPhones","16187833433")
                        $paramsFromTicket.Add("UsageLocation","US")
                    }
                }
            }
            "unique-Company-Name-6"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","uniqueParentCompany.DK")  
                        $paramsFromTicket.Add("Country","DK")
                        $paramsFromTicket.Add("OfficePhone","14598244999")
                        $extensionAttributes.Add("co","Denmark")
                        $extensionAttributes.Add("countryCode","208")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","DK")
                        $paramsFromTicket.Add("BusinessPhones","14598244999")
                        $paramsFromTicket.Add("UsageLocation","DK")
                    }
                }
            }
            "unique-Company-Name-4"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","uniqueParentCompany.com.br")  
                        $paramsFromTicket.Add("Country","BR")
                        $paramsFromTicket.Add("OfficePhone","1.55E+12")
                        $extensionAttributes.Add("co","Brazil")
                        $extensionAttributes.Add("countryCode","076")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","BR")
                        $paramsFromTicket.Add("BusinessPhones","1.55E+12")
                        $paramsFromTicket.Add("UsageLocation","BR")
                    }
                }
            }
            "unique-Office-Location-16"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","anonSubsidiary-1.com")  
                        $paramsFromTicket.Add("Country","BR")
                        $paramsFromTicket.Add("OfficePhone","1.55E+12")
                        $extensionAttributes.Add("co","Brazil")
                        $extensionAttributes.Add("countryCode","076")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","BR")
                        $paramsFromTicket.Add("BusinessPhones","1.55E+12")
                        $paramsFromTicket.Add("UsageLocation","BR")
                    }
                }
            }
            "unique-Company-Name-2"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme) 
                        $paramsFromTicket.Add("Server","@uniqueParentCompany-alcoil.com")   
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("OfficePhone","17173477500")
                        $extensionAttributes.Add("co","United States")
                        $extensionAttributes.Add("countryCode","840")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("BusinessPhones","17173477500")
                        $paramsFromTicket.Add("UsageLocation","US")
                    }
                }
            }
            "unique-Office-Location-18"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","@uniqueParentCompanyacs.cn")   
                        $paramsFromTicket.Add("Country","CN")
                        $paramsFromTicket.Add("OfficePhone","8.66E+12")
                        $extensionAttributes.Add("co","China")
                        $extensionAttributes.Add("countryCode","156")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","CN")
                        $paramsFromTicket.Add("BusinessPhones","8.66E+12")
                        $paramsFromTicket.Add("UsageLocation","CN")
                    }
                }
            }
            "unique-Company-Name-10"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = "US-MN-VS-DC01"
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","@uniqueParentCompanymn.com")    
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("OfficePhone","15074468005")
                        $extensionAttributes.Add("co","United States")
                        $extensionAttributes.Add("countryCode","840")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("BusinessPhones","15074468005")
                        $paramsFromTicket.Add("UsageLocation","US")
                    }
                }
            }
            "unique-Company-Name-11"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","@uniqueParentCompanylmp.ca")  
                        $paramsFromTicket.Add("Country","CA")
                        $paramsFromTicket.Add("OfficePhone","14506299864")
                        $extensionAttributes.Add("co","Canada")
                        $extensionAttributes.Add("countryCode","840")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","CA")
                        $paramsFromTicket.Add("BusinessPhones","14506299864")
                        $paramsFromTicket.Add("UsageLocation","CA")
                    }
                }
            }
            "unique-Office-Location-21"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","@uniqueParentCompanyselect.com")   
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("OfficePhone","18447859506")
                        $extensionAttributes.Add("co","United States")
                        $extensionAttributes.Add("countryCode","840")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","US")
                        $paramsFromTicket.Add("BusinessPhones","18447859506")
                        $paramsFromTicket.Add("UsageLocation","US")
                    }
                }
            }
            "unique-Company-Name-8"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "$localCred"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","@uniqueParentCompany.de")     
                        $paramsFromTicket.Add("Country","DE")
                        $paramsFromTicket.Add("OfficePhone","49215969560")
                        $extensionAttributes.Add("co","Germany")
                        $extensionAttributes.Add("countryCode","276")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","DE")
                        $paramsFromTicket.Add("BusinessPhones","49215969560")
                        $paramsFromTicket.Add("UsageLocation","DE")
                    }
                }
            }
            "unique-Company-Name-17"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "anonSubsidiary-1-Hybrid-Worker"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","@anonSubsidiary-1.com")    
                        $paramsFromTicket.Add("Country","MY")
                        $paramsFromTicket.Add("OfficePhone","60380707255")
                        $extensionAttributes.Add("co","Malaysia")
                        $extensionAttributes.Add("countryCode","458")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","MY")
                        $paramsFromTicket.Add("BusinessPhones","60380707255")
                        $paramsFromTicket.Add("UsageLocation","MY")
                    }
                }
            }
            "unique-Company-Name-16"{
                switch ($refUserSynching) {
                    $true {
                        $currentUserID = $jiraUserToModify
                        $hybridWorkerGroup = $null
                        $hybridWorkerCred = "anonSubsidiary-1-Hybrid-Worker"
                        $paramsFromTicket.Add("Identity",$SAMAccountNAme)
                        $paramsFromTicket.Add("Server","@anonSubsidiary-1.com")    
                        $paramsFromTicket.Add("Country","CN")
                        $paramsFromTicket.Add("OfficePhone","8.62E+11")
                        $extensionAttributes.Add("co","China")
                        $extensionAttributes.Add("countryCode","156")
                     }
                    $false {
                        $paramsFromTicket.Add("UserID",$jiraUserToModify)
                        $paramsFromTicket.Add("Country","CN")
                        $paramsFromTicket.Add("BusinessPhones","8.62E+11")
                        $paramsFromTicket.Add("UsageLocation","CN")
                    }
                }
            }
            Default {Write-Output "There is no matching location."}
        }
        
        
        If ($refUserSynching){
            
            Write-Output "I am on line 3161 before I run the commands to modify a user on their Local AD and sync`n`n"
            Write-Output "Hybrid Worker Group Performing this Operation: $hybridWorkerGroup"
            Write-Output "Hybrid Worker User Credential Object is $hybridWorkerCred" 
        
            Write-Output "`n`SAMAccountName: $SAMAccountName"
        
            Write-Output "Parameters from the Ticket:`n"
            $ParamsFromTicket | Format-Table 
            Write-Output "`n$($paramsFromTicket.GetType()) is the type of the parameter block paramsFromTicket`n"
            
            Write-Output "`n`nExtension Attributes:"
            $extensionAttributes | Format-Table
            Write-Output "`n$($extensionAttributes.GetType()) is the type of the parameter block extensionAttributes`n"

            $runbookParameters = [ordered]@{"Key"="$key";ParamsFromTicket=$paramsFromTicket;"extensionAttributes"=$extensionAttributes;"hybridWorkerCred"="$hybridWorkerCred";"currentUserID"="$currentUserID";"newManagerUPN"=$newManagerUPN}
            try{
            Write-Output "Executing: 'User-Change-3-LicenseUpdate'"
            $licenseParameters = [ordered]@{"paramsFromTicket" = $extensionAttributes; "currentUserID" = "$currentUserID"}
            start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name "User-Change-3-LicenseUpdate" -ResourceGroupName "uniqueParentCompanyGIT" -Parameters $licenseParameters -wait -ErrorAction Stop
            Write-Output "Executing: 'User-Change-2-LocalAD-72'"
            start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name "User-Change-2-LocalAD-72" -ResourceGroupName "uniqueParentCompanyGIT"  -RunOn $hybridWorkerGroup -Parameters $runbookParameters -wait -ErrorAction Stop
            Write-Output "Executing: 'Invoke-uniqueParentCompany-Sync'"
            start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name "Invoke-uniqueParentCompany-Sync" -ResourceGroupName "uniqueParentCompanyGIT" -RunOn "US-AZ-VS-DC01" -Wait -ErrorAction Stop
            
            Set-SuccessfulCommentRunbook -successMessage "This has been resolved by Automation!" -key $key -jiraHeader $jiraHeader -ErrorAction Stop
            exit 0
            }
            catch {
                $errorMessage = $_
                Write-Output $errorMessage    
                Set-PrivateErrorJiraRunbook
                Set-PublicErrorJira
                $ErrorActionPreference = "Stop"
                exit 1
        }
        }
        Else{
            Write-Output "I am on line 3199 before I run the commands to modify a user on Graph`n`n"
            Write-Output "UPN: $jiraUserToModify"
            $ParamsFromTicket | Format-Table
            if ($null -ne $newManagerUPN){
                Write-Output "New Manger UPN: $newManagerUPN"
            } 
            $runbookParameters = [ordered]@{"Key"="$key";"OriginUPN" = "$jiraUserToModify";"ParamsFromTicket"=$ParamsFromTicket;"newManagerUPN" = $newManagerUPN}
            Write-Output "Executing: '$Runbook'"
            try{
            start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name $Runbook -ResourceGroupName "uniqueParentCompanyGIT"  -Parameters $runbookParameters -wait -ErrorAction Stop
            if($officeAppNeeds -eq '10755'){
                Write-Output "This user requires a local account created and their license changed to E5. This is a WIP!"
            }
            Set-SuccessfulCommentRunbook -successMessage "This has been resolved by Automation!" -key $key -jiraHeader $jiraHeader -ErrorAction Stop
            exit 0
            }
            catch{
                $errorMessage = $_
                Write-Output $errorMessage
                Set-PrivateErrorJiraRunbook
                Set-PublicErrorJira
                $ErrorActionPreference = "Stop"  
                exit 1
            }
        }
    }
}
# SIG # Begin signature block
# MIIuqwYJKoZIhvcNAQcCoIIunDCCLpgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC3Kdt38CaoXzbu
# pIlLTxpptxGpo5LWWL24YWWBW/Nd+KCCFAUwggWQMIIDeKADAgECAhAFmxtXno4h
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBLb6cjMykppsIGfRxpxquOK
# LFp+aMfIGAIQ6LXJIz9PMA0GCSqGSIb3DQEBAQUABIICAARKEhOs2DMdBIWJnU0I
# LjV3LAxoxQmUr1clEK6NjBNPkn+ILD9ae/JjIUncvThd2R7oPghSpJV79PAvCI4e
# IdJQI/Ex6iSNyldM8FOkrl2LBdLPhIePnJqzn6Xpl0Ys1zb+ZJnP14BmZxa5IL8O
# D6q5O4uj6nfqtsGQq/nvxLJPdOkF/rZWfcetGYboPQCA+QeMrlzLpJ3GjO77nkW4
# 1C60vzNxqG/6Kj7iutCz5aA2FydP/T1IdJs+zwO5HzhrUPPCEwAuxE+ypPfsgzRk
# P1eN4jFFcj8Whs90oJV3Hx6pW01lqYS0d+Co7HctmBaxALO5MFCJJpjYk2X4qB73
# dY35+h+pM9c6ll29Szf3TQ2lnMFXssBmTP6umxDktF6p2hLnd1o67x+q8U2wXolJ
# 18F1JHhC+z00pHekPJwoCnazkIUEEgen184KHv/6ICARB/kTlai0PtOLmvzrWq0I
# q1fipD/iQaZlolixsvVDzVQ8Q+cylM4pwTVAUyRNhMGqW/2BjPqLYorm81Ba4FTh
# +s1KzJc+FtSF4VvVxVI9m7UTqqUJHITNAK9SRZh5yunER8Q2dyWfQVnUW4jinYub
# 7xTW7w0wssbQBUUBTXexyU16R1ImGxvaR56o0eohEZjUFV5WQ776nT81aUU2Jg+U
# hIeCXLZl/EqR64P/Gpsr1VegoYIWyTCCFsUGCisGAQQBgjcDAwExgha1MIIWsQYJ
# KoZIhvcNAQcCoIIWojCCFp4CAQMxDTALBglghkgBZQMEAgEwgeUGCyqGSIb3DQEJ
# EAEEoIHVBIHSMIHPAgEBBgkrBgEEAaAyAgMwMTANBglghkgBZQMEAgEFAAQgeN9n
# EWPAx2vMlhcWPBBmNWd5cOb3YpJaF/mLugHLZc4CFCTpj0BG48NRQj3k6JdtkfXL
# cDx2GA8yMDI1MDMxMzE4NDc0MVowAwIBAaBgpF4wXDELMAkGA1UEBhMCQkUxGTAX
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
# 9w0BCQQxIgQgsZHOhZGaWgFD+XqMOZhXClLsOvDFM1qXW2qLD0hXuhAwgbAGCyqG
# SIb3DQEJEAIvMYGgMIGdMIGaMIGXBCALeaI5rkIQje9Ws1QFv4/NjlmnS4Tu4t7D
# 2XHB6hc07DBzMF+kXTBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2ln
# biBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBT
# SEEzODQgLSBHNAIQARl1dHHJktdE36WW67lwFTANBgkqhkiG9w0BAQsFAASCAYBM
# cDYJw161Efn3Zp2aAIl81/GKT6Ig30MDIsTTmEn+QW4PUClq49Gula3MgYu3hqSL
# +leHtGMyAs5GH2AMAipIGfbdoDrshIylycVRwEq+tYJioOgx6Yeb2QlxPN6n2mrn
# Av0DFu8gaD4XKu3XUq2aVPujmg3XshPx1fxa043TkvNgBJX1s0GmM6nMJzNbiPDd
# 4U3xwPhlJodMJkOZreNeAv52+Jsfm82VOsH2nenqBGnJ8V8dcZUlBn0behv0PPjm
# 9J6FilSpr/vw4KOxS0Fc/jxq3NBQgsPcABRmWtiCN13gLfS8+OKAtjDa5bsf+NM5
# gxNijuvzDoSbGuMVMpekC7JjhRLec2gUAp/ZsEf7sKTyISGaCuH+V8mU7kW1F6h1
# Q+DjN+g9Gwnpmec8Ip4HH3Zbs8dIVgEG1hB3GzOkFTNbRw2N0BPvPnjOQukLdLER
# qhyNfXtZcm6F1h0nAKqGqLA48hEB/IeuGUZay7dwQovmGIQVcDwO9z+cG76tM2I=
# SIG # End signature block
































