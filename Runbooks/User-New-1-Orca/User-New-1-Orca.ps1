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
    $response = Invoke-RestMethod -Uri "https://uniqueParentCompany.atlassteamMember.net/rest/api/2/issue/$key/transitions" -Method Post -Body $jsonPayload -Headers $jiraHeader -ContentType "application/json"
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
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Import-module Az.Accounts
Import-Module Az.KeyVault
Connect-ExchangeOnline -ManagedIdentity -Organization uniqueParentCompany.onmicrosoft.com
Connect-AzAccount -subscription 'ea460e20-c6e3-46c7-9157-101770757b6b' -Identity
#Connect to: Graph / Via: Secret

#The Tenant ID from App Registrations
$graphTenantId      = "9e228334-bae6-4c7e-8b7f-9b0824082151"

# Construct the authentication URL
$graphURI           = "https://login.microsoftonline.com/$graphTenantId/oauth2/v2.0/token"

#The Client ID from App Registrations
$graphAppClientId   = "56cb7f72-67ee-4531-96d7-39a4e2b53555"

$graphRetrSecret    = Get-AzKeyVaultSecret -VaultName "US-TT-VAULT" -Name "GITGraphApi" -AsPlainText

# Construct the body to be used in Invoke-WebRequest
$graphAuthBody    = @{
    client_id     = $graphAppClientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret =  $graphRetrSecret
    grant_type    = "client_credentials"
}

# Get Authentication Token
$graphTokenRequest = Invoke-WebRequest -Method Post -Uri $graphURI -ContentType "application/x-www-form-urlencoded" -Body $graphAuthBody -UseBasicParsing

# Extract the Access Token
$graphSecureToken = ($graphTokenRequest.content | convertfrom-json).access_token | ConvertTo-SecureString -AsPlainText -force
$now = Get-Date -Format "HH:mm"
Write-Output "[$now] | Attempting to connect to Graph"
Connect-MgGraph -NoWelcome -AccessToken $graphSecureToken -ErrorAction Stop
#Connect to Jira via the API Secret in the Key Vault
$jiraRetrSecret = Get-AzKeyVaultSecret -VaultName "US-TT-Vault" -Name "JiraAPI" -AsPlainText

$hybridWorkerGroup      =   $null
$hybridWorkerCred       =   $null
$extensionAttributes    =   @{}


#Jira via the API or by Read-Host 
If ($null -eq $jiraRetrSecret){
    $jiraRetrSecret = Read-Host "Enter the API Key" -MaskInput
}
else{
    $null
}



#Jira
$jiraText = "david.drosdick@uniqueParentCompany.com:$jiraRetrSecret"
$jiraBytes = [System.Text.Encoding]::UTF8.GetBytes($jiraText)
$jiraEncodedText = [Convert]::ToBase64String($jiraBytes)
$jiraHeader         = @{
    "Authorization" = "Basic $jiraEncodedText"
    "Content-Type"  = "application/json"
}
#Pull the values from Jira
$TicketNum = $Key
$form = Invoke-RestMethod -Method get -uri "https://uniqueParentCompany.atlassteamMember.net/rest/api/2/issue/$TicketNum" -Headers $jiraHeader


<#CustomField_10787 is "New Departments" which is a select list (cascading) in Jira. 
#$LocationHired is the first selectable value, the $DepartmentString is the second value, for departments at the hired location. 
#The trim subexpressions are just to ensure that there are no trailing spaces.
#Customfield_10738 is the Jira CustomField "Work Location", which assigns the user to Office or Shop. This is also used for License / Group Assignment#>
$companyHired           =   $form.fields.customfield_10756.value
$locationHired          =   $form.fields.customfield_10787.value.Trim()
$department             =   $form.fields.customfield_10787.child.value.Trim()
$workLocation           =   $form.fields.customfield_10738.value
$shopOrOffice           =   $workLocation
$employeeType           =   $form.fields.customfield_10736.value
$softwareNeeds          =   $form.fields.customfield_10747.value
$officeAppNeeds         =   $form.fields.customfield_10751.ID


#Proper casing for job title
$jobtitle               =   $form.fields.customfield_10695.substring(0,1).toUpper()+$form.fields.customfield_10695.substring(1).toLower()
$jobtitle               =   $jobtitle.trim()
$TextInfo               =   (Get-Culture).TextInfo
$jobtitle               =   $TextInfo.ToTitleCase($jobtitle)

#As we allow for someone to use a different preferred First Name instead of their Given Name, we account for that here.
if (($null -eq $form.fields.customfield_10743) -or ($form.fields.customfield_10743 -eq ' ') -or ($form.fields.customfield_10743 -eq '')){
    $givenName          =   $form.fields.customfield_10722
}
else{
    $givenName          =   $form.fields.customfield_10743
}
$surName                =   $form.fields.customfield_10723
$formattedGivenName     =   Format-Name -inputName $givenName
$formattedSurName       =   Format-Name -inputName $surName
$displayName            =   $formattedGivenName , $formattedSurName -join " "
$mailNickName           =   ($formattedGivenName , $formattedSurName -join ".").replace(' ','')

$managerUPN             =   $form.fields.customfield_10765.emailaddress

#Get a token to make the various edits for the user and the manager
$tokenRequest           =   Invoke-WebRequest -Method Post -Uri $graphURI -ContentType "application/x-www-form-urlencoded" -Body $graphAuthBody -UseBasicParsing
$baseToken              =   ($tokenRequest.content | convertfrom-json).access_token
$graphAPIHeader         =   @{
    "Authorization"     =   "Bearer $baseToken"
    "Content-Type"      =   "application/JSON"
    grant_type          =   "client_credentials"
}

#Retreive the Manager and create the hashtable to assign to the user later.
$baseGraphAPI           =   "https://graph.microsoft.com/"
$APIVersion             =   "v1.0/"
$userEndPoint           =   "users/"
$managerGraphURI        =   $baseGraphAPI , $APIVersion , $userEndPoint , $managerUPN -join ""
$apiResponse            =   Invoke-RestMethod -Method Get -uri $managerGraphURI -Headers $graphAPIHeader
$managerID              =   $apiResponse.ID
$managerURI             =   $baseGraphAPI , $APIVersion , $userEndPoint , $managerID -join ""

$managerSetBody         =   @{
    '@odata.id'         =  "$managerURI"
  } | ConvertTo-JSON -Depth 2



if ($shopOrOffice -eq "Shop"){
    if($officeAppNeeds -eq '10775'){
        $shopOrOffice   =   "Shop Office"
    }
}
<#
    Variable Construction: This pulls all location specific variables for the next items.    
#>
<#  ShopOrOffice:
    Shop Office Users and Office Users should be Hybrid Synching Users with E5 Licenses
        A Shop Office User is any Shop User who requires 'Local Office Apps'
    Shop Users should have an F3 license, non-synching.
#>
<#  Work Location:
    Shop Office Users and Shop Users should be members of the same groups
    Office Users Belong to Specific Groups
#>

switch ($locationHired) {
    "unique-Office-Location-0"{
        $usageLoc                           =   "US"
        [string] $officePhone               =   "+1 410 756 2600"
        $upnSuffix                          =   "uniqueParentCompany.com"
        switch ($shopOrOffice) {
            "Shop"{
                $hybridWorkerGroup          =   $null
                $hybridWorkerCred           =   $null
                }
            Default{
                $hybridWorkerGroup          =   "US-AZ-VS-DC01"
                $hybridWorkerCred           =   "Testing-TT-Credential"
                $defaultOU                  =   'OU=New User Default - Synching,DC=uniqueParentCompany,DC=COM'
                $server                     =   "uniqueParentCompany.com"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                     = "Antigena-Email-Include"
                $group2                     = "Taneytown-Shop"
                $group3                     = "Taneytown Shop Distro"
                }
            "Office"{
                $group1                     =   "Antigena-Email-Include"
                $group2                     =   "Taneytown-Office"
                $group3                     =   "Taneytown Office Distro"
            }
        }
    }
    "unique-Office-Location-1"{
        $usageLoc                           =   "US"
        [string] $officePhone               =   "15596732207"
        $upnSuffix                          =   "uniqueParentCompanywest.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup          =   $null
                $hybridWorkerCred           =   $null
                }
            Default {
                $hybridWorkerGroup          =   "US-AZ-VS-DC01"
                $hybridWorkerCred           =   "Testing-TT-Credential"
                $defaultOU                  =   $null
                $server                     =   "uniqueParentCompanyWest.com"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                     =   "Antigena-uniqueParentCompanyWest"
                $group2                     =   "unique-Office-Location-1 - General"
                $group3                     =   "unique-Office-Location-1 Distro"
            }
            "Office"{
                $group1                     =   "Antigena-uniqueParentCompanyWest"
                $group2                     =   "unique-Office-Location-1 - General"
                $group3                     =   "unique-Office-Location-1 Distro"
            }
        }
    }
    "unique-Office-Location-2"{
        $usageLoc                           =   "US"
        [string] $officePhone               =   "12179233431"
        $upnSuffix                          =   "uniqueParentCompanymw.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup          =   $null
                $hybridWorkerCred           =   $null
                }
            Default {
                $hybridWorkerGroup          =   "US-AZ-VS-DC01"
                $hybridWorkerCred           =   "Testing-TT-Credential"
                $defaultOU                  =   'OU=New Users,OU=End Users,OU=AD-Midwest,DC=greenup,DC=uniqueParentCompany,DC=com'
                $server                     =   "uniqueParentCompanyMW.COM"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                     =   "Antigena-uniqueParentCompanyMW"
                $group2                     =   "Greenup"
                $group3                     =   "unique-Office-Location-2 Distro"
            }
            "Office"{
                $group1                     =   "Antigena-uniqueParentCompanyMW"
                $group2                     =   "Greenup"
                $group3                     =   "unique-Office-Location-2 Distro"
            }
        }
    }
    "unique-Office-Location-3"{
        $usageLoc                           =   "US"
        [string] $officePhone               =   "17126573223"
        $upnSuffix                          =   "uniqueParentCompanyia.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup          =   $null
                $hybridWorkerCred           =   $null
                }
            Default {
                $hybridWorkerGroup          =   $null
                $hybridWorkerCred           =   $null
                $defaultOU                  =   $null
                $server                     =   "uniqueParentCompanyIA.COM"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                     =   "Antigena-IA"
                $group2                     =   "Iowa"
                $group3                     =   "unique-Office-Location-3 Distro"
                }
            "Office"{
                $group1                     =   "Antigena-IA"
                $group2                     =   "Iowa"
                $group3                     =   "unique-Office-Location-3 Distro"
            }
        }
    }
    "unique-Company-Name-20"{
        $usageLoc                           =   "US"
        [string] $officePhone               =   "19797780095"
        $upnSuffix                          =   "anonSubsidiary-1corp.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup          =   $null
                $hybridWorkerCred           =   $null
                }
            Default {
                $hybridWorkerGroup          =   "US-AZ-VS-DC01"
                $hybridWorkerCred           =   "Testing-TT-Credential"
                $defaultOU                  =   'OU=New User Default - Synching,OU=anonSubsidiary-1,DC=anonSubsidiary-1CORP,DC=LOCAL'
                $server                     =   "anonSubsidiary-1Corp.com"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                     =   "Antigena-anonSubsidiary-1"
                $group2                     =   "anonSubsidiary-1"
                $group3                     =   "anonSubsidiary-1 Shop Staff"
                }
            "Office"{
                $group1                     =   "Antigena-anonSubsidiary-1"
                $group2                     =   "anonSubsidiary-1"
                $group3                     =   "anonSubsidiary-1 Office Staff"
            }
        }
    }
    "unique-Company-Name-7"{
        $usageLoc                           =   "BE"
        [string] $officePhone               =   "3212395029"
        $upnSuffix                          =   "uniqueParentCompany.be"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup          =   $null
                $hybridWorkerCred           =   $null
                }
            Default {
                $hybridWorkerGroup          =   $null
                $hybridWorkerCred           =   $null
                $defaultOU                  =   $null
                $server                     =   "uniqueParentCompany.BE"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                     =   $null
                $group2                     =   $null
                $group3                     =   $null
                }
            "Office"{
                $group1                     =   $null
                $group2                     =   $null
                $group3                     =   $null
            }
        }
    }
    "unique-Office-Location-6"{
        $usageLoc                           =   "IT"
        [string] $officePhone               =   "39029399041"
        $upnSuffix                          =   "uniqueParentCompany.it"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup          =   $null
                $hybridWorkerCred           =   $null
                }
            Default {
                $hybridWorkerGroup          =   $null
                $hybridWorkerCred           =   $null
                $defaultOU                  =   $null
                $server                     =   "uniqueParentCompany.IT"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                      =   $null
                $group2                      =   $null
                $group3                      =   $null
                }
            "Office"{
                $group1                      =   $null
                $group2                      =   $null
                $group3                      =   $null
            }
        }
    }
    "uniqueParentCompany (Sondrio) Europe, S.rl.l."{
        $usageLoc                            =   "IT"
        [string] $officePhone                =   "39029399041"
        $upnSuffix                           =   "uniqueParentCompany.it"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup           =   $null
                $hybridWorkerCred            =   $null
                }
            Default {
                $hybridWorkerGroup           =   $null
                $hybridWorkerCred            =   $null
                $defaultOU                   =   $null
                $server                      =   "uniqueParentCompany.IT"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                      =   $null
                $group2                      =   $null
                $group3                      =   $null
                }
            "Office"{
                $group1                      =   $null
                $group2                      =   $null
                $group3                      =   $null
            }
        }
    }
    "unique-Office-Location-8"{
        $usageLoc                            =  "CN"
        [string] $officePhone                =  "861000000000"
        $upnSuffix                           =  "uniqueParentCompanychina.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup           =  $null
                $hybridWorkerCred            =  $null
                }
            Default {
                $hybridWorkerGroup           =  $null
                $hybridWorkerCred            =  $null
                $defaultOU                   =  $null
                $server                      =  "uniqueParentCompanyCHINA.COM"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                       = $null
                $group2                       = $null
                $group3                       = $null
                }
            "Office"{
                $group1                       = $null
                $group2                       = $null
                $group3                       = $null
            }
        }
    }
    "unique-Office-Location-9"{
        $usageLoc                             = "CN"
        [string] $officePhone                 = "861000000000"
        $upnSuffix                            = "uniqueParentCompanychina.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup            = $null
                $hybridWorkerCred             = $null
                }
            Default {
                $hybridWorkerGroup            = $null
                $hybridWorkerCred             = $null
                $defaultOU                    = $null
                $server                      =  "uniqueParentCompanyCHINA.COM"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                       = $null
                $group2                       = $null
                $group3                       = $null
                }
            "Office"{
                $group1                       = $null
                $group2                       = $null
                $group3                       = $null
            }
        }
    }
    "unique-Company-Name-3"{
        $usageLoc                             =   "AU"
        [string] $officePhone                 =   "861000000000"
        $upnSuffix                            =   "uniqueParentCompany.com.au"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup            =   $null
                $hybridWorkerCred             =   $null
                }
            Default {
                $hybridWorkerGroup            =   $null
                $hybridWorkerCred             =   $null
                $defaultOU                    =   $null
                $server                       =   "uniqueParentCompany.COM.AU"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                       =   $null
                $group2                       =   $null
                $group3                       =   $null
                }
            "Office"{
                $group1                       =   $null
                $group2                       =   $null
                $group3                       =   $null
            }
        }
    }
    "unique-Company-Name-18"{
        $usageLoc                              =  "US"
        [string] $officePhone                  =  "19133225165"
        $upnSuffix                             =  "anonSubsidiary-1.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup             =  $null
                $hybridWorkerCred              =  $null
                }
            Default {
                $hybridWorkerGroup             =  "US-AZ-VS-DC01"
                $hybridWorkerCred              =  "Testing-TT-Credential"
                $defaultOU                     =  'OU=New User Default - Synching,OU=Users,OU=anonSubsidiary-1,DC=anonSubsidiary-1inc,DC=lan'
                $server                        =  "anonSubsidiary-1.COM"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                        =  "{anonSubsidiary-1 Direct Benefit Employees}"
                $group2                        =  "{anonSubsidiary-1 KS Office}"
                $group3                        =  "{anonSubsidiary-1 Staff}"
                }
            "Office"{
                $group1                        =  "{anonSubsidiary-1 Direct Benefit Employees}"
                $group2                        =  "{anonSubsidiary-1 KS Office}"
                $group3                        =  "{anonSubsidiary-1 Staff}"
            }
        }
    }
    "unique-Company-Name-5"{
        $usageLoc                               =  "US"
        [string] $officePhone                   =  "19083792665"
        $upnSuffix                              =  "uniqueParentCompanydc.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                }
            Default {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                $defaultOU                      =  $null
                $server                         =  "uniqueParentCompanyDC.COM"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                         =  "Antigena-uniqueParentCompanyDC"
                $group2                         =  "uniqueParentCompany Dry Cooling"
                $group3                         =  "uniqueParentCompany Dry Cooling Distro"
                }
            "Office"{
                $group1                         =  "Antigena-uniqueParentCompanyDC"
                $group2                         =  "uniqueParentCompany Dry Cooling"
                $group3                         =  "uniqueParentCompany Dry Cooling Distro"
            }
        }
    }
    "unique-Company-Name-21"{
        $usageLoc                               =  "US"
        [string] $officePhone                   =  "13368242102"
        $upnSuffix                              =  "towercomponentsinc.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                }
            Default {
                $hybridWorkerGroup              =  "US-AZ-VS-DC01"
                $hybridWorkerCred               =  "Testing-TT-Credential"
                $defaultOU                      =  'OU=New User Default - Synching,OU=AAD Connect Sync OU,DC=TOWERCOMPONENTS,DC=local'
                $server                         =  "TOWERCOMPONENTSINC.COM"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                         =  "Antigena-anonSubsidiary-1"
                $group2                         =  "anonSubsidiary-1"
                $group3                         =  "anonSubsidiary-1 Shop Distro"
                }
            "Office"{
                $group1                         =  "Antigena-anonSubsidiary-1"
                $group2                         =  "anonSubsidiary-1"
                $group3                         =  "anonSubsidiary-1 Office Distro"
            }
        }
    }
    "unique-Office-Location-27"{
        $usageLoc                               =  "US"
        [string] $officePhone                   =  "16187833433"
        $upnSuffix                              =  "uniqueParentCompanymw.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                }
            Default {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                $defaultOU                      =  $null
                $server                         =  "uniqueParentCompanyMW.COM"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                         =  "Antigena-uniqueParentCompanyMW"
                $group2                         =  "anonSubsidiary-1"
                $group3                         =  "unique-Office-Location-2 Distro"
                }
            "Office"{
                $group1                         =  "Antigena-uniqueParentCompanyMW"
                $group2                         =  "anonSubsidiary-1"
                $group3                         =  "unique-Office-Location-2 Distro"
            }
        }
    }
    "unique-Company-Name-6"{
        $usageLoc                               =  "DK"
        [string] $officePhone                   =  "14598244999"
        $upnSuffix                              =  "uniqueParentCompany.DK"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                }
            Default {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                $defaultOU                      =  $null
                $server                         =  "uniqueParentCompany.DK"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                         =  $null
                $group2                         =  $null
                $group3                         =  $null
                }
            "Office"{
                $group1                         =  $null
                $group2                         =  $null
                $group3                         =  $null
            }
        }
    }
    "unique-Company-Name-4"{
        $usageLoc                               =  "BR"
        [string] $officePhone                   =  "1.55E+12"
        $upnSuffix                              =  "uniqueParentCompany.COM.BR"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                }
            Default {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                $defaultOU                      =  $null
                $server                         =  "uniqueParentCompany.COM.BR"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                         =  $null
                $group2                         =  $null
                $group3                         =  $null
                }
            "Office"{
                $group1                         =  $null
                $group2                         =  $null
                $group3                         =  $null
            }
        }
    }
    "unique-Office-Location-16"{
        $usageLoc                               =  "BR"
        [string] $officePhone                   =  "1.55E+12"
        $upnSuffix                              =  "anonSubsidiary-1.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                }
            Default {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                $defaultOU                      =  $null
                $server                         =  "anonSubsidiary-1.COM"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                         =  $null
                $group2                         =  $null
                $group3                         =  $null
                }
            "Office"{
                $group1                         =  $null
                $group2                         =  $null
                $group3                         =  $null
            }
        }
    }
    "unique-Company-Name-2"{
        $usageLoc                               =  "US"
        [string] $officePhone                   =  "17173477500"
        $upnSuffix                              =  "uniqueParentCompany-alcoil.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                }
            Default {
                $hybridWorkerGroup              =  "US-AZ-VS-DC01"
                $hybridWorkerCred               =  "Testing-TT-Credential"
                $defaultOU                      =  $null
                $server                         =  "uniqueParentCompany-ALCOIL.COM"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                         =  "Antigena-Alcoil"
                $group2                         =  "uniqueParentCompany-Alcoil"
                $group3                         =  "uniqueParentCompany Alcoil Shop Distro"
                }
            "Office"{
                $group1                         =  "Antigena-Alcoil"
                $group2                         =  "uniqueParentCompany-Alcoil"
                $group3                         =  "uniqueParentCompany Alcoil Office Distro"
            }
        }
    }
    "unique-Office-Location-18"{
        $usageLoc                               =  "CN"
        [string] $officePhone                   =  "8.66E+12"
        $upnSuffix                              =  "uniqueParentCompanyacs.cn.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                }
            Default {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                $defaultOU                      =  $null
                $server                         =  "uniqueParentCompanyACS.CN"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                         =  $null
                $group2                         =  $null
                $group3                         =  $null
                }
            "Office"{
                $group1                         =  $null
                $group2                         =  $null
                $group3                         =  $null
            }
        }
    }
    "unique-Company-Name-10"{
        $usageLoc                               =  "US"
        [string] $officePhone                   =  "15074468005"
        $upnSuffix                              =  "uniqueParentCompanymn.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                }
            Default {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                $defaultOU                      =  $null
                $server                         =  "uniqueParentCompanyMN.COM"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                         =  "Antigena-MN"
                $group2                         =  "uniqueParentCompany Minnesota Distro"
                $group3                         =  "Minnesota"
                }
            "Office"{
                $group1                         =  "Antigena-MN"
                $group2                         =  "uniqueParentCompany Minnesota Distro"
                $group3                         =  "Minnesota"
            }
        }
    }
    "unique-Company-Name-11"{
        $usageLoc                               =  "CA"
        [string] $officePhone                   =  "14506299864"
        $upnSuffix                              =  "uniqueParentCompanylmp.ca"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                }
            Default {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                $defaultOU                      =  $null
                $server                         =  "uniqueParentCompanyLMP.CA"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                         =  $null
                $group2                         =  $null
                $group3                         =  $null
                }
            "Office"{
                $group1                         =  $null
                $group2                         =  $null
                $group3                         =  $null
            }
        }
    }
    "unique-Office-Location-21"{
        $usageLoc                               =  "US"
        [string] $officePhone                   =  "18447859506"
        $upnSuffix                              =  "uniqueParentCompanyselect.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                }
            Default {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                $defaultOU                      =  $null
                $server                         =  "uniqueParentCompanySELECT.COM"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                         =  "Antigena-uniqueParentCompanySelect"
                $group2                         =  "uniqueParentCompany Select Distro"
                $group3                         =  $null
                }
            "Office"{
                $group1                         =  "Antigena-uniqueParentCompanySelect"
                $group2                         =  "uniqueParentCompany Select Distro"
                $group3                         =  $null
            }
        }
    }
    "unique-Company-Name-8"{
        $usageLoc                               =  "DE"
        [string] $officePhone                   =  "49215969560"
        $upnSuffix                              =  "uniqueParentCompany.de"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                }
            Default {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                $defaultOU                      =  $null
                $server                         =  "uniqueParentCompany.DE"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                         =  "unique-Company-Name-8 Distro"
                $group2                         =  $null
                $group3                         =  $null
                }
            "Office"{
                $group1                         =  "unique-Company-Name-8 Distro"
                $group2                         =  $null
                $group3                         =  $null
            }
        }
    }
    "unique-Company-Name-17"{
        $usageLoc                               =  "MY"
        [string] $officePhone                   =  "60380707255"
        $upnSuffix                              =  "anonSubsidiary-1.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                }
            Default {
                $hybridWorkerGroup              =  "US-AZ-VS-DC01"
                $hybridWorkerCred               =  "Testing-TT-Credential"
                $defaultOU                      =  'OU=New User Default - Synching,OU=Users,OU=anonSubsidiary-1,DC=anonSubsidiary-1inc,DC=lan'
                $server                         =  "anonSubsidiary-1.COM"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                         =  "{anonSubsidiary-1 Asia-Pacific}"
                $group2                         =  $null
                $group3                         =  $null
                }
            "Office"{
                $group1                         =  "{anonSubsidiary-1 Asia-Pacific}"
                $group2                         =  $null
                $group3                         =  $null
            }
        }
    }
    "unique-Company-Name-16"{
        $usageLoc                               =  "CN"
        [string] $officePhone                   =  "8.62E+11"
        $upnSuffix                              =  "anonSubsidiary-1.com"
        switch ($shopOrOffice) {
            "Shop" {
                $hybridWorkerGroup              =  $null
                $hybridWorkerCred               =  $null
                }
            Default {
                $hybridWorkerGroup              =  "US-AZ-VS-DC01"
                $hybridWorkerCred               =  "Testing-TT-Credential"
                $defaultOU                      =  'OU=New User Default - Synching,OU=Users,OU=anonSubsidiary-1,DC=anonSubsidiary-1inc,DC=lan'
                $server                         =  "anonSubsidiary-1.COM"
            }
        }
        switch ($workLocation) {
            "Shop"{
                $group1                         =  "{anonSubsidiary-1 Asia-Pacific}"
                $group2                         =  $null
                $group3                         =  $null
                }
            "Office"{
                $group1                         =  "{anonSubsidiary-1 Asia-Pacific}"
                $group2                         =  $null
                $group3                         =  $null
            }
        }
    }
    Default {
            $now = Get-Date -Format "HH:mm"
            Write-Output "[$now] | There is no matching location."
        }
}
<#
    UsageLocation: As Usage Location is used to identify where their data resides, we use this to set the user's Country Attributes across AD and EID
#>
switch ($usageLoc) {
    "US"{
        $countryString            =     "United States" 
        $countryCode              =     840
    }
    "CA"{
        $countryString            =     "Canada" 
        $countryCode              =     124
    }
    "IT"{
        $countryString            =     "Italy" 
        $countryCode              =     380
    }
    "BR"{
        $countryString            =     "Brazil" 
        $countryCode              =     076
    }
    "DK"{
        $countryString            =     "Denmark" 
        $countryCode              =     208
    }
    "MY"{
        $countryString            =     "Malaysia" 
        $countryCode              =     458
    }
    "BE"{
        $countryString            =     "Belgium" 
        $countryCode              =     056
    }
    "CN"{
        $countryString            =     "China" 
        $countryCode              =     156
    }
    "AU"{
        $countryString            =     "Australia" 
        $countryCode              =     036
    }
    "DE"{
        $countryString            =     "Germany" 
        $countryCode              =     276
    }
    
    Default {
        $now = Get-Date -Format "HH:mm"
        Write-Output "[$now] | There is no matching location."
    }
}

$now = Get-Date -Format "HH:mm"
$generatedUPN = ($mailNickName , $upnSuffix -join '@').replace(' ','')
Write-output "[$now] | Variable Review: `
`nUserPrincipalName: $generatedUPN `
`ndisplayName: $displayName `
`nmailNickName: $mailNickName `
`ngivenName: $formattedGivenName `
`nsurName: $formattedSurName `
`nLocationHired: $locationHired `
`nUsageLocation: $usageLoc `
`nCountryString: $countryString `
`nCountyCode: $countryCode `
`nCompanyHired: $companyHired `
`nDepartment: $department `
`nWorkLocation: $workLocation | ShopOrOffice: $shopOrOffice `
`nEmployeeType: $employeeType `
`nsoftwareNeeds: $softwareNeeds `
`nOfficeAppNeeds: $officeAppNeeds `
`njobTitle: $jobTitle `
`nbyridWorkerGroup: $hybridWorkerGroup `
`nhybridWorkerCred: $hybridWorkerCred `
`ngroup1: $group1 `
`ngroup2: $group2 `
`ngroup3: $group3 `
`ndefaultOU: $defaultOU `n`n`n"





$date = get-date $form.fields.customfield_10613
$DoW = $date.DayOfWeek.ToString()
$Month = (Get-date $date -format "MM").ToString()
$Day = (Get-date $date -format "dd").ToString()
$pw = $DoW+$Month+$Day+"!"

$PasswordProfile = @{
    Password = $pw
}
$extensionAttributes = @{
    extensionAttribute1	     = $shopOrOffice
} | ConvertTo-JSON -Depth 3

$newUserHashTable = @{
    accountEnabled                      =   $true
    ShowInAddressList                   =   $true
    country                             =   $countryString
    businessPhones                      =   @($officePhone)
    department                          =   $department
    displayName                         =   $displayName
    givenName                           =   $formattedGivenName
    jobTitle                            =   $jobtitle
    mailNickname                        =   $mailNickName
    passwordProfile                     =   $PasswordProfile
    officeLocation                      =   $locationHired
    surname                             =   $formattedSurName
    usageLocation                       =   $usageLoc
    userPrincipalName                   =   $generatedUPN
    <# 
    The following are Parameters that can be utilized in the API
    City / Postal Code / Preferred Language / State could have utility

    Preferred Language: User Selected
    Street Address / Postal Code / City / State: Derived from Office Location

    Mobile Phone is a privacy risk.

    streetAddress                       =   "$streetAddress"
    postalCode                          =   "$zipCode"
    city                                =   "$city"
    state                               =   "$state"
    preferredLanguage                   =   "$preferredLanguage"
    mobilePhone                         =   "$mobilePhone"
    #>
}
$newUserJSON        =       $newUserHashTable | ConvertTo-JSON -depth 5
$createNewUserURI   =       $baseGraphAPI , $APIVersion , $userEndPoint.trim('/') -join ""
#Create the New User and get their ID
$createResponse     =       Invoke-RestMethod -uri $createNewUserURI -Method Post -Body $newUserJSON -Headers $graphAPIHeader 
$newUserID          =       $createResponse.ID
$newUserGraphURI    =       $baseGraphAPI , $APIVersion , $userEndPoint , $newUserID -join ""

#The below should be refactored into a POST/PATCH/PUT whenever the API starts accepting the attributes
Update-MGBetaUser -UserId $newUserID -OnPremisesExtensionAttributes $extensionAttributes -CompanyName $companyHired
#Assign the User to a Manager
$assignManagerURI   =       $newUserGraphURI , "/manager/`$ref" -join ""
$assignResponse     =       Invoke-RestMethod -Method Put -uri $assignManagerURI -body $managerSetBody -Headers $graphAPIHeader 
$assignResponse     |       Out-Null
#This is where License Assignment Occurs
switch ($shopOrOffice){
    "Shop" {
        $licenses   =   @("SPE_F1","POWER_BI_STANDARD")
        $licStr     =   @("F3","Power BI Standard")
    }
    Default {
        $licenses   =   "SPE_E5"
        $licStr     =   "E5"
    }
}
$now = Get-Date -Format "HH:mm"
Write-Output "[$now] | License to add: $license | License String: $licStr"


ForEach ($license in $licenses){
    $sku = Get-MgSubscribedSku -All | Where-Object -Property SkuPartNumber -eq $license
    $remLisc = $sku.prepaidunits.enabled - $sku.consumedunits 
    if ($remlisc -le 0){ 
        $now = Get-Date -Format "HH:mm"
        Write-Output "[$now] $licStr Needs Purchased"
        Set-LicenseNeedPurchased -Continue=$true -license $licStr
    }
    Else{
        $newSKU = $sku.skuID
        $addLicenseJSONBody = @{
            addLicenses = @(
                @{
                disabledPlans   = @()
                skuId           = $newSKU
            }
            )
            removeLicenses = @()
        } | ConvertTo-JSON -depth 10
        $addLicenseJSONBody
        $addLicenseURI = $newUserGraphURI , "/assignLicense" -join ""
        Invoke-RestMethod -uri $addLicenseURI -Body $addLicenseJSONBody -Headers $graphAPIHeader -Method Post
    }
}

$noMailbox = $true
while ($noMailbox){
    $now = Get-Date -Format "HH:mm"
    Write-Output "[$now] | Checking for $generatedUPN"
    $newMailbox = Get-Mailbox -Identity $generatedUPN -errorAction SilentlyContinue
    if(!($newMailbox)){
        $now = Get-Date -Format "HH:mm"
        Write-Output "[$now] | $generatedUPN does not yet exist as a mailbox"
        Start-Sleep -Milliseconds 500
    }
    else{
        $now = Get-Date -Format "HH:mm"
        Write-Output "[$now] | $generatedUPN has a mailbox!"
        $noMailbox = $false
    }
}



#This is where the users get added to their Specific Groups
#ID Security Group
if ($Department -eq "Executive"){
    $group4 = "IDSecurity-Executive Leadership"
}
Elseif ($usageLoc -in "IT","BE","DE","DK","GB"){
$null
}
Else{
    if ($licStr.count -ge 2){
        $licStr = "F3"
    }
$group4 = "IDSecurity-"+$licStr+"-"+$usageLoc
}

$groups = @($group1,$group2,$group3,$group4)
ForEach ($group in $groups){
    if ($group -eq "" -or $null -eq $group){
        $now = Get-Date -Format "HH:mm"
        Write-Output "[$now] | Group is null"
    } 
    else{
        $groupObjID = (Get-MGGroup -Search "displayname:$group" -ConsistencyLevel:eventual -top 1).ID
        try{
            New-MGGroupMember -GroupId $groupObjID -DirectoryObjectId $newUserID -erroraction stop
        } 
        catch {
                $now = Get-Date -Format "HH:mm"
                Write-Output "[$now] | An error occurred while adding the user to the Azure AD group. Trying to add to the distribution group instead."
            try{
                $distro = Get-DistributionGroup -Identity $group
                Add-DistributionGroupMember -Identity $distro.ID -member $newUserID -BypassSecurityGroupManagerCheck -erroraction stop
            }
            catch{
                $now = Get-Date -Format "HH:mm"
                Write-Output "[$now] | Unable to add $displayName to $group. Please do this manually."
            }
        }
    }
}
#Adds the User to the MFA Enabled Group
New-MgGroupMember -GroupId "276cd6bd-7e8f-483b-9e33-6b6e364bdd50" -DirectoryObjectId $newUserID

#The following creates the user on their Local AD if they require a local AD account.
if ($shopOrOffice -ne 'Shop'){
    if ($null -ne $hybridWorkerGroup){
        $createLADParameters = @{}
        $now                                        =  Get-Date -Format "HH:mm"
        Write-Output "[$now] | $displayName requires a Local Domain Account."    
        $formattedOU = $defaultOU.Replace(",","~")
        $createLADParameters.Add('TargetPath',$formattedOU)
        $createLADParameters.Add('Server',$server)
        $localADParameters                          =  [ordered]@{
            "Key"                                   =  "$key";`
            "destinationLADParameters"              =  $createLADParameters; `
            "destinationHybridWorkerCred"           =  "$hybridWorkerCred"; `
            "newUPN"                                =  "$generatedUPN"
        }
        $localADParameters
        $now                                        =  Get-Date -Format "HH:mm"
        Write-Output "[$now] | Executing: 'User-Transfer-5-Create-Local-From-Graph-72'"
        start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name "User-Transfer-5-Create-Local-From-Graph-72" -ResourceGroupName "uniqueParentCompanyGIT" -RunOn $hybridWorkerGroup -Parameters $localADParameters -Wait
        $now                                        =  Get-Date -Format "HH:mm"
        Write-Output "[$now] | Executing: 'Invoke-uniqueParentCompany-Sync'"
        start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name "Invoke-uniqueParentCompany-Sync" -ResourceGroupName "uniqueParentCompanyGIT" -RunOn "US-AZ-VS-DC01" -Wait
    }
    Else{
        $now                                        =  Get-Date -Format "HH:mm"
        $publicErrorMEssage                         = "[$now] | $locationHired is not configured for a Hybrid Worker Runbook.",`
                                                    " $displayName Local Account will need to be done manually" -join ""
        Write-output $publicErrorMEssage
        #Set-PublicErrorJira -key $key -publicErrorMessage $publicErrorMEssage -jiraHeader $jiraHeader
    }
}

<#For CoPilot, as this is fully a manual process, a comment is made on a subtask for the CoPilot Team
to add the required users into whatever groups are required.
#>
If (($softwareNeeds -contains 'CoPilot') -or ($workLoc -eq "Shop")){
    $subTaskKey = ($form.fields.subtasks | Where-Object {($_.Fields -like "*CoPilot*")}).key


    $payload = @{
        "update" = @{
            "customfield_10718" = @(@{
                "set" = "$emailAddr"
            })
        }
    }
# Convert the payload to JSON
$jsonPayload = $payload | ConvertTo-Json -Depth 10
Invoke-RestMethod -Uri "https://uniqueParentCompany.atlassteamMember.net/rest/api/2/issue/$($subTaskKey)" -Method Put -Body $jsonPayload -Headers $headers
}

<#From the above, the user is created either on both Entra ID and Local AD, or just Entra ID
We then evaluate their software needs. If a user has 'Sage' or 'Doclink' as required software
we add their user account to two Active Directory Groups on unique-Office-Location-0's Domain, 'uniqueParentCompany.com'
Group 1:Citrix Cloud W11M Desktop Users
Group 2: DocLink Users

If a user is NOT an unique-Office-Location-0 Employee, with their primary account on said domain controller:
The most critical thing is that their primary UPN must be set as their email attribute.
Name:               Primary Account Display Name
Country:            US 
DisplayName:        Primary Account Display Name
UserPrincipalName:  The same as their standard UPN, except with @uniqueParentCompany.com instead of their specific domain suffix. 
OfficePhone:        14107562600
Company:            Not Affiliated 
Title:              DocLink User
AccountPassword:    The same as their intial Standard User Account Password prior to reset. 
Department:         Service Account
GivenName:          GivenName
Office:             unique-Office-Location-0
Path:               "OU=CompuData - External Sage Users - Non-Synching,DC=uniqueParentCompany,DC=COM" `
Surname:            Surname
Server:             uniqueParentCompany.COM
EmailAddress:       !!!Their Primary Email Address!!!
#>
If (($softwareNeeds -contains 'Sage') -or ($softwareNeeds -contains 'DocLink')){
    $now = Get-Date -Format "HH:mm"
    Write-Output "[$now] | $displayName requires CompuData Access"
    $compuDataHybridWorkerGroup                 =  "US-AZ-VS-DC01"
    if($locationHired -eq 'unique-Office-Location-0'){
        $existingCitrixUser                     =  $true
    }
    else{
        $existingCitrixUser                     =  $false
    }
    $now = Get-Date -Format "HH:mm"
    Write-Output "[$now] | Executing: 'User-New-2-Citrix-Doclink-Sage'"
    $citrixADParameters                             =  [ordered]@{ `
        "existingCitrixUser"                        =  $existingCitrixUser;`
        "destinationHybridWorkerCred"               =  "$hybridWorkerCred"; `
        "originUPN"                                 =  "$generatedUPN"; `
        "mailNickName"                              =  "$mailNickName"; `
        "startDate"                                 =  "$date"; `
        "displayName"                               =  "$displayName"; `
        "firstName"                                 =  "$formattedGivenName"; `
        "lastName"                                  =  "$formattedSurName"

    }
    start-azautomationrunbook -AutomationAccountName "GIT-Infrastructure-Automation" -Name "User-New-2-Citrix-Doclink-Sage" -ResourceGroupName "uniqueParentCompanyGIT" -RunOn "$compuDataHybridWorkerGroup" -Parameters $citrixADParameters -Wait
    Set-SuccessfulCommentRunbook -successMessage "New User Has been Created! UPN: $generatedUPN Password: $pw  CompuData Account: " -jiraHeader $jiraHeader -key $Key
}
else{
    $now = Get-Date -Format "HH:mm"
    Write-output "[$now] | Compudata and Citrix Not needed"
    Set-SuccessfulCommentRunbook -successMessage "New User Has been Created! UPN: $generatedUPN Password: $pw " -key $key -jiraHeader $jiraHeader
}
# SIG # Begin signature block
# MIIumQYJKoZIhvcNAQcCoIIuijCCLoYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBs0vaHfxnC8jUc
# Q1ho49bPuQ8SR/RR6hIxnSiBNNVHtKCCFAUwggWQMIIDeKADAgECAhAFmxtXno4h
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
# anBZbb3T3Kf7DmGQDth6MYIZ6jCCGeYCAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUG
# A1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQg
# RzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAOeHFNrWpQ
# adD+X7fviblJMA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKA
# AKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEID7nOlfO6VaQRAiX7dQ0nAke
# UWPXy4wkY6EvJ20qnWwfMA0GCSqGSIb3DQEBAQUABIICAHnVwewPRd1p1MYAuX/5
# wx4/6AKDfxcHd8SGzQDagHfC66hJb6tMbsJJf7YuFpgE5/IOT68LpwbV0HHPp5pO
# TbLXgAYw8LizPLsivNTOq/le69xcqp4x27mh55nYsQu6yCGyLjirTs6fww71pGSA
# l8k5kRGomok86300DEGoV9RI8aAqmEJefofmfxqFwfZTDHBJeBSQSXGDy8bKDM9y
# ymgsGIkZxdEhM07U4KYPFyPzcc5vGYc0Cq/10eoh46iyJlo8YPQQl33g1XOg9dHj
# HPhDnhW5T1Q+5XKWCNgO72pJd86vdtaMnnjratHVM7CmM0rycaWdiNOhvNatnfCQ
# R/zXxI+PvM6Pq3iwkD1jgmjc4j9uAQp6mvWgeErFrWM6ATz5az1/698VSrD3NFMv
# 9BIBuvFTSAkaSfj/RAW0LlDUnI+vniRD53SY/3nFZJRTJg0ENmwgwWSBehRQ2pN5
# X+SpIEguYmEDgLYXQmw15NdN+12chijfWtHWNdV4SS8v39cgSbBqvzY04nZHeSeo
# 2aSHSXl2KfMqqjLydk6xxci5MYT95VLl3dF7v6dgCOlpwbOw558ny/jFx2RHW3Nq
# DKwAt6drBXKwzAUtTUgd9o1PGlzZ/V1C7R3A1H71VcyqxKXqMCqhxRF5Rown0C6j
# TRMZDJdJAFHVtnlhzzYf9spIoYIWtzCCFrMGCisGAQQBgjcDAwExghajMIIWnwYJ
# KoZIhvcNAQcCoIIWkDCCFowCAQMxDTALBglghkgBZQMEAgEwgdwGCyqGSIb3DQEJ
# EAEEoIHMBIHJMIHGAgEBBgkrBgEEAaAyAgMwMTANBglghkgBZQMEAgEFAAQgwIPg
# WeO9Js3tisrJFSvMVVNJgyZWZInLcVVDYH0nuUUCFGkWvqg4f0OrOHshI4CgUxH6
# GYpQGA8yMDI1MDQyNDE0MDYxNlowAwIBAaBXpFUwUzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoMEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMMIEdsb2JhbHNpZ24gVFNB
# IGZvciBBZHZhbmNlZCAtIEc0oIISSjCCBmIwggRKoAMCAQICEAEDMuFlv5t4Q+CZ
# dZRjdwswDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEds
# b2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5n
# IENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzAxWhcNMzQxMjEwMDAwMDAw
# WjBTMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEpMCcG
# A1UEAwwgR2xvYmFsc2lnbiBUU0EgZm9yIEFkdmFuY2VkIC0gRzQwggGiMA0GCSqG
# SIb3DQEBAQUAA4IBjwAwggGKAoIBgQC+JXo5QxiuddbVs6HIm9Ymnp6AFjdZrvTn
# J4O4KsPMxDqvLLcu68jav8MFr3ls1zYS2rYzXjENJ/PhPQOBG7M77kRoJp4z5Mj1
# JiUv4JDZA0f0JmVdQcS8rAkBIT3sGSBGL0AfbGW91TNlveIgpETFWnAjLUSqtkbK
# gHnqPL47bMhpuDIKV0jiCQRzOq+BcygWcvkbE7c49EY4N+npJSP57DC2giCg/hO3
# YApe+2L4b4W8fBs3r3ZP72NR/BEAlwWWuiTbX0eg2iw8LIfIMU3MyObEXSN8pmKT
# aL/MplcAc7p9yluDLJNATCJ9uX3Mb2+dNYSCHyqZ1wGRCs2j0Bgw8ZZMezzXVM18
# PnhenlcyWHk6C0Vzmpjh2K0l/vjC9Ajrz6trIPxnl5Ry9XjG/1IYyilNK8bYoNbI
# wzB7MBqEGEn0tszc1tTaHh0RQoEvzrCelYFi3JcxSBaRk8wK2YipbvGWm2/lyDvJ
# QD8fXUFP+gAtDE6VcRvVSawwkMtKGE8CAwEAAaOCAagwggGkMA4GA1UdDwEB/wQE
# AwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQU2Te2M0VujzUH
# zvepswr9oKnI+YIwVgYDVR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQw
# MgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRv
# cnkvMAwGA1UdEwEB/wQCMAAwgZAGCCsGAQUFBwEBBIGDMIGAMDkGCCsGAQUFBzAB
# hi1odHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9nc3RzYWNhc2hhMzg0ZzQw
# QwYIKwYBBQUHMAKGN2h0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzdHNhY2FzaGEzODRnNC5jcnQwHwYDVR0jBBgwFoAU6hbGaefjy1dFOTOk8EC+
# 0MO9ZZYwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWduLmNv
# bS9jYS9nc3RzYWNhc2hhMzg0ZzQuY3JsMA0GCSqGSIb3DQEBDAUAA4ICAQBmH88E
# YcQnDDBjnRcpWHsx9D3GkugAavxN8Xn4ZyxS8YdPVDHm9oBP1zw7gQ2jkdQKy3pa
# bMFSC0L5KQbMM34XmmdI/8PnI6vxNNyJ+xw/PBfVkZ+9jcaJEgVTDnaRBqslnWcn
# iHL9Q29hKa5m9ryMIrjDXrOf368ag0X9sO9uFF9Oy7pi2FUTQ7R+HSJe6pasn3fn
# J93urP7ljSRjshdGJPVN8Oom5AFZqPVtiakjEcnEPHAu7LxP5LqtxoM7HEjmaKs5
# 9zCmpDSw41abvc+xod+ka7pQq6lRXb2QwIISzxYlxsVXPuycrJVahcm2wjpM1LzB
# NPG73ccEYyDAwYD0kkBq4RrCkRnc5/TD91SfUKRwrgK9vb95+LRknaOzedxzPtFg
# WIJnrIisxmo8u/f+KUTn5GpkEMzPonq4LYGtHDWqvYSvJ6W6woQdDUgPqgaU8YIH
# 9JnM5VL3mRfiBeiFuPjScQW9v6VBX8n0qoNz0fhtw/oE0pAIP3XEtA5OX9CY6tLq
# pE4wOMNC96neBY2TXdLDbQEwiCFk+xTep7DEjQbVkj115kd1PfAHxtP+de/0gcYg
# oALzlsdIZg0wnaVCX0d72pNjsQZWUUMX7nQIPNBsvFydseV5W03AWsgB4Q9o7Zvd
# RXRIJRRcUjNOZkvwCXgxMNvS1WU5UbBgTGMekDCCBlkwggRBoAMCAQICDQHsHJJA
# 3v0uQF18R3QwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBS
# b290IENBIC0gUjYxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2Jh
# bFNpZ24wHhcNMTgwNjIwMDAwMDAwWhcNMzQxMjEwMDAwMDAwWjBbMQswCQYDVQQG
# EwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UEAxMoR2xvYmFs
# U2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBHNDCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAPAC4jAj+uAb4Zp0s691g1+pR1LHYTpjfDkjeW10
# /DHkdBIZlvrOJ2JbrgeKJ+5Xo8Q17bM0x6zDDOuAZm3RKErBLLu5cPJyroz3mVpd
# dq6/RKh8QSSOj7rFT/82QaunLf14TkOI/pMZF9nuMc+8ijtuasSI8O6X9tzzGKBL
# mRwOh6cm4YjJoOWZ4p70nEw/XVvstu/SZc9FC1Q9sVRTB4uZbrhUmYqoMZI78np9
# /A5Y34Fq4bBsHmWCKtQhx5T+QpY78Quxf39GmA6HPXpl69FWqS69+1g9tYX6U5lN
# W3TtckuiDYI3GQzQq+pawe8P1Zm5P/RPNfGcD9M3E1LZJTTtlu/4Z+oIvo9Jev+Q
# sdT3KRXX+Q1d1odDHnTEcCi0gHu9Kpu7hOEOrG8NubX2bVb+ih0JPiQOZybH/LIN
# oJSwspTMe+Zn/qZYstTYQRLBVf1ukcW7sUwIS57UQgZvGxjVNupkrs799QXm4mbQ
# DgUhrLERBiMZ5PsFNETqCK6dSWcRi4LlrVqGp2b9MwMB3pkl+XFu6ZxdAkxgPM8C
# jwH9cu6S8acS3kISTeypJuV3AqwOVwwJ0WGeJoj8yLJN22TwRZ+6wT9Uo9h2ApVs
# ao3KIlz2DATjKfpLsBzTN3SE2R1mqzRzjx59fF6W1j0ZsJfqjFCRba9Xhn4QNx1r
# GhTfAgMBAAGjggEpMIIBJTAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQU6hbGaefjy1dFOTOk8EC+0MO9ZZYwHwYDVR0jBBgwFoAU
# rmwFo5MT4qLn4tcc1sfwf8hnU6AwPgYIKwYBBQUHAQEEMjAwMC4GCCsGAQUFBzAB
# hiJodHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDYGA1UdHwQvMC0w
# K6ApoCeGJWh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vcm9vdC1yNi5jcmwwRwYD
# VR0gBEAwPjA8BgRVHSAAMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2Jh
# bHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEBDAUAA4ICAQB/4ojZV2cr
# Ql+BpwkLusS7KBhW1ky/2xsHcMb7CwmtADpgMx85xhZrGUBJJQge5Jv31qQNjx6W
# 8oaiF95Bv0/hvKvN7sAjjMaF/ksVJPkYROwfwqSs0LLP7MJWZR29f/begsi3n2HT
# tUZImJcCZ3oWlUrbYsbQswLMNEhFVd3s6UqfXhTtchBxdnDSD5bz6jdXlJEYr9yN
# mTgZWMKpoX6ibhUm6rT5fyrn50hkaS/SmqFy9vckS3RafXKGNbMCVx+LnPy7rEze
# +t5TTIP9ErG2SVVPdZ2sb0rILmq5yojDEjBOsghzn16h1pnO6X1LlizMFmsYzeRZ
# N4YJLOJF1rLNboJ1pdqNHrdbL4guPX3x8pEwBZzOe3ygxayvUQbwEccdMMVRVmDo
# fJU9IuPVCiRTJ5eA+kiJJyx54jzlmx7jqoSCiT7ASvUh/mIQ7R0w/PbM6kgnfIt1
# Qn9ry/Ola5UfBFg0ContglDk0Xuoyea+SKorVdmNtyUgDhtRoNRjqoPqbHJhSsn6
# Q8TGV8Wdtjywi7C5HDHvve8U2BRAbCAdwi3oC8aNbYy2ce1SIf4+9p+fORqurNIv
# eiCx9KyqHeItFJ36lmodxjzK89kcv1NNpEdZfJXEQ0H5JeIsEH6B+Q2Up33ytQn1
# 2GByQFCVINRDRL76oJXnIFm2eMakaqoimzCCBYMwggNroAMCAQICDkXmuwODM8OF
# ZUjm/0VRMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9v
# dCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxT
# aWduMB4XDTE0MTIxMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowTDEgMB4GA1UECxMX
# R2xvYmFsU2lnbiBSb290IENBIC0gUjYxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzAR
# BgNVBAMTCkdsb2JhbFNpZ24wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQCVB+hzymb57BTKezz3DQjxtEULLIK0SMbrWzyug7hBkjMUpG9/6SrMxrCIa8W2
# idHGsv8UzlEUIexK3RtaxtaH7k06FQbtZGYLkoDKRN5zlE7zp4l/T3hjCMgSUG1C
# Zi9NuXkoTVIaihqAtxmBDn7EirxkTCEcQ2jXPTyKxbJm1ZCatzEGxb7ibTIGph75
# ueuqo7i/voJjUNDwGInf5A959eqiHyrScC5757yTu21T4kh8jBAHOP9msndhfuDq
# jDyqtKT285VKEgdt/Yyyic/QoGF3yFh0sNQjOvddOsqi250J3l1ELZDxgc1Xkvp+
# vFAEYzTfa5MYvms2sjnkrCQ2t/DvthwTV5O23rL44oW3c6K4NapF8uCdNqFvVIrx
# clZuLojFUUJEFZTuo8U4lptOTloLR/MGNkl3MLxxN+Wm7CEIdfzmYRY/d9XZkZeE
# CmzUAk10wBTt/Tn7g/JeFKEEsAvp/u6P4W4LsgizYWYJarEGOmWWWcDwNf3J2iiN
# GhGHcIEKqJp1HZ46hgUAntuA1iX53AWeJ1lMdjlb6vmlodiDD9H/3zAR+YXPM0j1
# ym1kFCx6WE/TSwhJxZVkGmMOeT31s4zKWK2cQkV5bg6HGVxUsWW2v4yb3BPpDW+4
# LtxnbsmLEbWEFIoAGXCDeZGXkdQaJ783HjIH2BRjPChMrwIDAQABo2MwYTAOBgNV
# HQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUrmwFo5MT4qLn
# 4tcc1sfwf8hnU6AwHwYDVR0jBBgwFoAUrmwFo5MT4qLn4tcc1sfwf8hnU6AwDQYJ
# KoZIhvcNAQEMBQADggIBAIMl7ejR/ZVSzZ7ABKCRaeZc0ITe3K2iT+hHeNZlmKlb
# qDyHfAKK0W63FnPmX8BUmNV0vsHN4hGRrSMYPd3hckSWtJVewHuOmXgWQxNWV7Oi
# szu1d9xAcqyj65s1PrEIIaHnxEM3eTK+teecLEy8QymZjjDTrCHg4x362AczdlQA
# Iiq5TSAucGja5VP8g1zTnfL/RAxEZvLS471GABptArolXY2hMVHdVEYcTduZlu8a
# HARcphXveOB5/l3bPqpMVf2aFalv4ab733Aw6cPuQkbtwpMFifp9Y3s/0HGBfADo
# mK4OeDTDJfuvCp8ga907E48SjOJBGkh6c6B3ace2XH+CyB7+WBsoK6hsrV5twAXS
# e7frgP4lN/4Cm2isQl3D7vXM3PBQddI2aZzmewTfbgZptt4KCUhZh+t7FGB6ZKpp
# Q++Rx0zsGN1s71MtjJnhXvJyPs9UyL1n7KQPTEX/07kwIwdMjxC/hpbZmVq0mVcc
# pMy7FYlTuiwFD+TEnhmxGDTVTJ267fcfrySVBHioA7vugeXaX3yLSqGQdCWnsz5L
# yCxWvcfI7zjiXJLwefechLp0LWEBIH5+0fJPB1lfiy1DUutGDJTh9WZHeXfVVFsf
# rSQ3y0VaTqBESMjYsJnFFYQJ9tZJScBluOYacW6gqPGC6EU+bNYC1wpngwVayaQQ
# MYIDSTCCA0UCAQEwbzBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2ln
# biBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBT
# SEEzODQgLSBHNAIQAQMy4WW/m3hD4Jl1lGN3CzALBglghkgBZQMEAgGgggEtMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDArBgkqhkiG9w0BCTQxHjAcMAsGCWCG
# SAFlAwQCAaENBgkqhkiG9w0BAQsFADAvBgkqhkiG9w0BCQQxIgQgMnJRJNsXuFXK
# MvAKwR7Cmkkw9Dwtt92xkBsn3UF9XBswgbAGCyqGSIb3DQEJEAIvMYGgMIGdMIGa
# MIGXBCCRkkebYjW5dia/tgFteAiRg3ID2HORwGwbjj13/+LHNzBzMF+kXTBbMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTExMC8GA1UEAxMo
# R2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBTSEEzODQgLSBHNAIQAQMy4WW/
# m3hD4Jl1lGN3CzANBgkqhkiG9w0BAQsFAASCAYB1pAOQsIyVpI2j8nbNLnw/prye
# Ll+x/lRxcTXQfFtBn3i2Ay/uB74y6Z4iLpoOZQDpK5CKASLzgumH8uz7GIx2qSAl
# a6Q9gGGO6SnFPBkuCTHr/K1SVUXi0idriKc7FWRDpOY4ZikpdbBQrbBhgV9tBix4
# VajhAFH/qXU8tV2RBCdZxt5x0ncdJbOEfzijOGzaIEGO3VF6l4iSiwz0t4fqsilk
# hJCFG2s4ErGoTcVCxm6lMFhzi6UjCUj5X+h4hutxfx0ylNrqDeF2Mj1ruK1kSw3e
# sn+MkR+ocy4Qh63FmCdHzB16ZcriFsgkno++F0ip5gAAKHYLDphA5HD7nTfVcqls
# hhqKa3JXKT4BjsCrybF6xhyQVN5bglAxQnJhRZYnBkz33ywakEAI0uLr1HblblwV
# HdnOQKsF1vesziOAGTp/lmozUtMDlbF3sF/xBX6v/N+nxNj8ZLE60nT+BP3UNJHW
# HxRSirh9VunrE9Y7haBqPAfdx+6z/w8jY5EZ0Mo=
# SIG # End signature block


































