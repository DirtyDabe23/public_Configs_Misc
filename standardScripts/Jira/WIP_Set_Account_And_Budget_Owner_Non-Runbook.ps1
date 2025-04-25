param(
    [string] $reporter,
    [string] $accountNumber,
    [string] $ghdKey,
    [string] $procKey   
)

#Items that are pushed into the Procurement Ticket from the Automation on Creation
$reporter = "Automation For Jira"
$procKey = "PROC-695"
$ghdKey = "GHD-29752"
$accountNumber = $null


#Values that will need to be determined by the parent ticket.
$officeLocation = $null 
$department = $null 

#GHD Ticket for Data Retrieval
$Issue = Invoke-RestMethod -Method get -uri "https://uniqueParentCompany.atlassteamMember.net/rest/api/2/issue/$ghdKey" -Headers $headers

$officeLocation = $issue.fields.customfield_10787.value
$officeLocationID =  [int]$issue.fields.customfield_10787.id 
$department = $issue.fields.customfield_10787.child.value
$departmentID = [int]$issue.fields.customfield_10787.child.id 


$ttProduction = "Assembly" `
, "Cage/Inventory" `
, "Coil - Non-Welder" `
, "Coil - Welder" `
, "Control Panel" `
, "Electrical" `
, "Evaporator" `
, "Evaporator Coil" `
, "Evaporator Support" `
, "High Side Custom Engineering" `
, "Low Side Assembly" `
, "Low Side Custom Engineering" `
, "Maintenance, Machinery, & Equipment" `
, "Manufacturing Engineering" `
, "Materials" `
, "Operator Associate" `
, "Parts" `
, "Plant Management" `
, "Production" `
, "Production Control" `
, "Quality - Office" `
, "Quality - Shop" `
, "Research & Development" `
, "Safety - Office" `
, "Safety - Shop" `
, "Sheet Metal" `
, "Shop Office" `
, "Stockroom, Warehouse, Part Order, Shipping" `
,"Sub-Assembly & Support","Traffic","Welding"

$validAccountNumber = "6680-01-01" `
, "6680-01-02"`
, "6680-01-03"`
, "6680-01-04"`
, "6680-01-05"`
, "6680-01-06"`
, "6680-01-07"`
, "6680-01-09"`
, "6680-01-12"`
, "6680-01-13"`
, "6680-01-14"`
, "6680-01-16"`
, "6680-02-00"`
, "6680-02-20"`
, "6680-03-00"`
, "6680-06-00"`
, "1310-01-00"`
, "1345-01-00"`
, "1346-01-00"`
, "1355-01-00"`
, "1380-01-00"`
, "1398-01-00"`
, "1554-01-00"`
, "1557-01-00"`
, "6850-01-00"`
, "1335-01-00"`
, "2600-03-00"`
, "1325-01-00"`
, "1318-01-00"







If ($null -eq $accountNumber)
{
    If ($officeLocation -eq 'unique-Office-Location-0')
    {
        if ($department -eq 'Marketing Refrigeration')
        {
            $accountNumber = "6680-01-01"
            $budgetOwner = "Joe Sunnarborg"
        }
        if ($department -eq 'Marketing HVAC')
        {
            $accountNumber = "6680-01-02"
            $budgetOwner = "Chad Nagle"
        }
        if ($department -eq 'Product Development - HVAC')
        {
            $accountNumber = "6680-01-03"
            $budgetOwner = "Jennifer Hamilton"
        }
        if ($department -in $ttProduction)
        {
            $accountNumber = "6680-01-04"
            $budgetOwner = "William Jones"
        }
        if ($department -eq 'Finance')
        {
            $accountNumber = "6680-01-05"
            $budgetOwner = "Jeff Finch"
        }
        if ($department -eq 'Executive')
        {
            $accountNumber = "6680-01-06"
            $budgetOwner = "Mike Hilker"
        }
        if ($department -eq 'Product Development')
        {
            $accountNumber = "6680-01-07"
            $budgetOwner = "Mark Huber"
        }
        if ($department -eq 'Product Development')
        {
            $accountNumber = "6680-01-07"
            $budgetOwner = "Mark Huber"
        }
        if ($department -eq 'Product Development - Refrigeration')
        {
            $accountNumber = "6680-01-09"
            $budgetOwner = "Trevor Hegg"
        }
        if ($department -eq 'uniqueParentCompanyld')
        {
            $accountNumber = "6680-01-12"
            $budgetOwner = "Kurt Leibendorfer"
        }
        if ($department -eq 'Water Systems')
        {
            $accountNumber = "6680-01-13"
            $budgetOwner = "Chris Nagle"
        }
        if ($department -eq 'People Operations')
        {
            $accountNumber = "6680-01-14"
            $budgetOwner = "Jeff Poczekaj"
        }
        if ($department -eq 'Global Information Technology')
        {
            $accountNumber = "6680-01-16"
            $budgetOwner = "Mike Hilker"
        }
        if ($department -eq 'Customer Solutions')
        {
            $accountNumber = "Unknown"
            $budgetOwner = "Unknown"
        }
    }
    If ($officeLocation -eq 'unique-Company-Name-2')
    {
        $accountNumber = "1398-01-00"
        $budgetOwner = "John Kollasch"
    }
    If ($officeLocation -eq 'unique-Company-Name-3')
    {
        $accountNumber = "1335-01-00"
        $budgetOwner = "Alex Eisold"
    }
    If ($officeLocation -eq 'unique-Company-Name-5')
    {
        $accountNumber = "1346-01-00"
        $budgetOwner = "Toby Athron"
    }
    If ($officeLocation -eq 'unique-Company-Name-7')
    {
        $accountNumber = "1310-01-00"
        $budgetOwner = "Ivan Jorissen"
    }
    If ($officeLocation -eq 'unique-Office-Location-3')
    {
        $accountNumber = "6680-06-00"
        $budgetOwner = "Brett Meyer"
    }
    If ($officeLocation -eq 'unique-Company-Name-11')
    {
        $accountNumber = "1554-01-00"
        $budgetOwner = "Jeffrey Gingras"
    }
    If ($officeLocation -eq 'unique-Office-Location-2')
    {
        $accountNumber = "6680-02-00"
        $budgetOwner = "Michael GteamMembernavola"
    }
    If ($officeLocation -eq 'unique-Office-Location-3')
    {
        $accountNumber = "6680-06-00"
        $budgetOwner = "Brett Meyer"
    }
    If ($officeLocation -eq 'unique-Office-Location-27')
    {
        $accountNumber = "6680-02-20"
        $budgetOwner = "Michael GteamMembernavola"
    }
    If ($officeLocation -eq 'unique-Office-Location-21')
    {
        $accountNumber = "1557-01-00"
        $budgetOwner = "Eric Staley"
    }
    If ($officeLocation -eq 'unique-Office-Location-1')
    {
        $accountNumber = "6680-03-00"
        $budgetOwner = "Doug Bradley"
    }
    If ($officeLocation -eq 'unique-Company-Name-18')
    {
        $accountNumber = "1345-01-00"
        $budgetOwner = "Don Dobney"
    }
    If ($officeLocation -eq 'unique-Company-Name-20')
    {
        $accountNumber = "1380-01-00"
        $budgetOwner = "Alex Eisold"
    }
    If ($officeLocation -eq 'unique-Company-Name-21')
    {
        $accountNumber = "1355-01-00"
        $budgetOwner = "BrteamMember Walker"
    }
}

Else
{
   If ($accountNumber -notin $validAccountNumber)
    {
        Write-Output "Account Number is Invalid. Reverting to Office Location and Department."
        If ($officeLocation -eq 'unique-Office-Location-0')
        {
            if ($department -eq 'Marketing Refrigeration')
            {
                $accountNumber = "6680-01-01"
                $budgetOwner = "Joe Sunnarborg"
            }
            if ($department -eq 'Marketing HVAC')
            {
                $accountNumber = "6680-01-02"
                $budgetOwner = "Chad Nagle"
            }
            if ($department -eq 'Product Development - HVAC')
            {
                $accountNumber = "6680-01-03"
                $budgetOwner = "Jennifer Hamilton"
            }
            if ($department -in $ttProduction)
            {
                $accountNumber = "6680-01-04"
                $budgetOwner = "William Jones"
            }
            if ($department -eq 'Finance')
            {
                $accountNumber = "6680-01-05"
                $budgetOwner = "Jeff Finch"
            }
            if ($department -eq 'Executive')
            {
                $accountNumber = "6680-01-06"
                $budgetOwner = "Mike Hilker"
            }
            if ($department -eq 'Product Development')
            {
                $accountNumber = "6680-01-07"
                $budgetOwner = "Mark Huber"
            }
            if ($department -eq 'Product Development')
            {
                $accountNumber = "6680-01-07"
                $budgetOwner = "Mark Huber"
            }
            if ($department -eq 'Product Development - Refrigeration')
            {
                $accountNumber = "6680-01-09"
                $budgetOwner = "Trevor Hegg"
            }
            if ($department -eq 'uniqueParentCompanyld')
            {
                $accountNumber = "6680-01-12"
                $budgetOwner = "Kurt Leibendorfer"
            }
            if ($department -eq 'Water Systems')
            {
                $accountNumber = "6680-01-13"
                $budgetOwner = "Chris Nagle"
            }
            if ($department -eq 'People Operations')
            {
                $accountNumber = "6680-01-14"
                $budgetOwner = "Jeff Poczekaj"
            }
            if ($department -eq 'Global Information Technology')
            {
                $accountNumber = "6680-01-16"
                $budgetOwner = "Mike Hilker"
            }
            if ($department -eq 'Customer Solutions')
            {
                $accountNumber = "Unknown"
                $budgetOwner = "Unknown"
            }
        }
        If ($officeLocation -eq 'unique-Company-Name-2')
        {
            $accountNumber = "1398-01-00"
            $budgetOwner = "John Kollasch"
        }
        If ($officeLocation -eq 'unique-Company-Name-3')
        {
            $accountNumber = "1335-01-00"
            $budgetOwner = "Alex Eisold"
        }
        If ($officeLocation -eq 'unique-Company-Name-5')
        {
            $accountNumber = "1346-01-00"
            $budgetOwner = "Toby Athron"
        }
        If ($officeLocation -eq 'unique-Company-Name-7')
        {
            $accountNumber = "1310-01-00"
            $budgetOwner = "Ivan Jorissen"
        }
        If ($officeLocation -eq 'unique-Office-Location-3')
        {
            $accountNumber = "6680-06-00"
            $budgetOwner = "Brett Meyer"
        }
        If ($officeLocation -eq 'unique-Company-Name-11')
        {
            $accountNumber = "1554-01-00"
            $budgetOwner = "Jeffrey Gingras"
        }
        If ($officeLocation -eq 'unique-Office-Location-2')
        {
            $accountNumber = "6680-02-00"
            $budgetOwner = "Michael GteamMembernavola"
        }
        If ($officeLocation -eq 'unique-Office-Location-3')
        {
            $accountNumber = "6680-06-00"
            $budgetOwner = "Brett Meyer"
        }
        If ($officeLocation -eq 'unique-Office-Location-27')
        {
            $accountNumber = "6680-02-20"
            $budgetOwner = "Michael GteamMembernavola"
        }
        If ($officeLocation -eq 'unique-Office-Location-21')
        {
            $accountNumber = "1557-01-00"
            $budgetOwner = "Eric Staley"
        }
        If ($officeLocation -eq 'unique-Office-Location-1')
        {
            $accountNumber = "6680-03-00"
            $budgetOwner = "Doug Bradley"
        }
        If ($officeLocation -eq 'unique-Company-Name-18')
        {
            $accountNumber = "1345-01-00"
            $budgetOwner = "Don Dobney"
        }
        If ($officeLocation -eq 'unique-Company-Name-20')
        {
            $accountNumber = "1380-01-00"
            $budgetOwner = "Alex Eisold"
        }
        If ($officeLocation -eq 'unique-Company-Name-21')
        {
            $accountNumber = "1355-01-00"
            $budgetOwner = "BrteamMember Walker"
        }
    }
   else 
   {
        switch ($accountNumber) {
            "6680-01-01"{$BudgetOwner = "Joe Sunnarborg"}
            "6680-01-02"{$BudgetOwner = "Chad Nagle"}
            "6680-01-03"{$BudgetOwner = "Jennifer Hamilton"}
            "6680-01-04"{$BudgetOwner = "William Jones"}
            "6680-01-05"{$BudgetOwner = "Jeff Finch"}
            "6680-01-06"{$BudgetOwner = "Mike Hilker"}
            "6680-01-07"{$BudgetOwner = "Mark Huber"}
            "6680-01-09"{$BudgetOwner = "Trevor Hegg"}
            "6680-01-12"{$BudgetOwner = "Kurt Leibendorfer"}
            "6680-01-13"{$BudgetOwner = "Chris Nagle"}
            "6680-01-14"{$BudgetOwner = "Jeff Poczekaj"}
            "6680-01-16"{$BudgetOwner = "Mike Hilker"}
            "6680-02-00"{$BudgetOwner = "Michael GteamMembernavola"}
            "6680-02-20"{$BudgetOwner = "Michael GteamMembernavola"}
            "6680-03-00"{$BudgetOwner = "Doug Bradley"}
            "6680-06-00"{$BudgetOwner = "Brett Meyer"}
            "1310-01-00"{$BudgetOwner = "Ivan Jorissen"}
            "1345-01-00"{$BudgetOwner = "Don Dobney"}
            "1346-01-00"{$BudgetOwner = "Toby Athron"}
            "1355-01-00"{$BudgetOwner = "BrteamMember Walker"}
            "1380-01-00"{$BudgetOwner = "Alex Eisold"}
            "1398-01-00"{$BudgetOwner = "John Kollasch"}
            "1554-01-00"{$BudgetOwner = "Jeffrey Gingras"}
            "1557-01-00"{$BudgetOwner = "Eric Staley"}
            "6850-01-00"{$BudgetOwner = "Comcast"}
            " 1335-01-00"{$BudgetOwner = "Alex Eisold"}
            "2600-03-00"{$BudgetOwner = "Doug Bradley"}
            "1325-01-00"{$BudgetOwner = "Cristina Garavaglia"}
            "1318-01-00"{$BudgetOwner = "Tina Lindkvist"}
        }
   } 

}


If (($null -eq $accountNumber) -and ($null -eq $budgetOwner))
{
    Write-Output "Not valid. Please contact GIT for Assistance"
    Exit 1 
}
else {
    $payload = @{
        "update" = @{
            "customfield_10721" = @(
                @{
                    "set" = "$accountNumber"
                }
            )
            "customfield_10787" = @(
                @{
                    "set" = $officeLocationID
                    "child" = @{
                        "set" = $departmentID
                    }
                }
            )
            "customfield_10872" = @(
                @{
                    "set" = "$BudgetOwner"
                }
            )
        }
    }
    
    # Convert the payload to JSON
    $jsonPayload = $payload | ConvertTo-Json -Depth 10
    
Invoke-RestMethod -Uri "https://uniqueParentCompany.atlassteamMember.net/rest/api/2/issue/$($procKey)" -Method Put -Body $jsonPayload -Headers $headers

}

# SIG # Begin signature block
# MIIuqwYJKoZIhvcNAQcCoIIunDCCLpgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA8D2EzVDgKWq4J
# /YaPhCeHcZFkrlInpShd67V1HJK5YqCCFAUwggWQMIIDeKADAgECAhAFmxtXno4h
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
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFWvZDPKU3btcJrWntqT3LaY
# IPQ2JWNkDDvk+rflJ444MA0GCSqGSIb3DQEBAQUABIICAFP+jKWQK/hs40aVnOo5
# QkG9MKEe4f/rGnYDU8kduP8sJYOjPpUFt+ME3HQOI59BrxOmk/c2LfqNlaJ2oKuR
# DQnZLMLNbLOhWCVk8Kvg1qTaP1Ufhw6sRDz3XAG+9lSDDKp76nYUnDnDpI4C6sxT
# 9aHNcHz0eDjmFjvuSbLObQGiBCMgPO6jCogT9OwFjMW2fsdx3KYxPXzKWPZtn5Hv
# G6OLi7xRxdP1Xh0q2PPGyz9oEQz3Pi+1YxXauV68HIwkzEkNLz/fCjv3PwCVKG7V
# Ew6dBW4b2n7vRFrFdlYGqNs9qvHU1CKqD+by1T5A62i0lXrRGSVxJebYEV8mmiji
# jQW5FaS8nM0GbibCHmqECMSkiTUZvPheYkNxWzr2DfAMKmvFoOUjUKZeqlcmCjXI
# w/niRYRrMvNNR8ESscHddsiKSpt4CwkQzEC1CWHlxmQuJTLzylTmejcmKc4yl852
# cT3XSKQ5fVyLHcSrBdy/nHiIPFPNdZmp3Obd5q3uiYL01ajcYxjPgXNR7gRyQNd7
# WXmtlr5sITHCTjx858oxlAS472pGeM0u4e1j8MWsL+bYF5K5wZo6Z5cbj5M7EaOA
# 3msy/TsUrKgqgYZewYH579GkWc+lwYwZReFTaZrGeEOcIQ/ShszCJQPgDcIkThqL
# 0fNP0s4uO0wJtkADCqc9ZFb/oYIWyTCCFsUGCisGAQQBgjcDAwExgha1MIIWsQYJ
# KoZIhvcNAQcCoIIWojCCFp4CAQMxDTALBglghkgBZQMEAgEwgeUGCyqGSIb3DQEJ
# EAEEoIHVBIHSMIHPAgEBBgkrBgEEAaAyAgMwMTANBglghkgBZQMEAgEFAAQgim/p
# v8a/aKZGZGzYN9mKbWnyOgXa6S9i/xiYNTB7ghgCFB8tIUst94ezyYYYLffHzbYc
# AkNwGA8yMDI0MTIxOTE4MDU1MlowAwIBAaBgpF4wXDELMAkGA1UEBhMCQkUxGTAX
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
# 9w0BCQQxIgQguXJ2TcRsLQ2+qNNfS/HolX/IkKVmtwVRBBqe7brjjwYwgbAGCyqG
# SIb3DQEJEAIvMYGgMIGdMIGaMIGXBCALeaI5rkIQje9Ws1QFv4/NjlmnS4Tu4t7D
# 2XHB6hc07DBzMF+kXTBbMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2ln
# biBudi1zYTExMC8GA1UEAxMoR2xvYmFsU2lnbiBUaW1lc3RhbXBpbmcgQ0EgLSBT
# SEEzODQgLSBHNAIQARl1dHHJktdE36WW67lwFTANBgkqhkiG9w0BAQsFAASCAYBA
# gGlHz9Sqj7wIRPvTvMOukkdcOXHWrTSit6NJk9Cyg/sOqPCO95s2ft79P0426KUv
# Opa0YWlThD0NVUhf9zxev97sYnlSpvH6eud07f336J8zZK9ZSUEJcoQbXeLX4vhE
# bGp1yS8piBmgkuTmBHby4wSx8iCkqNMtN3SKGtf8gZ4AtGD0JGA/k2tFoc6majq0
# dKtsm1S7g3GbwYl1+YBGet6W4ONs9n6auhP4HybmOv9+Yca1978+s4KDc6CSYPC0
# QvEm5vsJvBxMm7C2JPxNQLWiAqRKChiE9sVbpiZ1dwKqECDobHYw10cHEkOOqVpr
# cMGrDC/Pvf0egB+pduIwMp23oQk6VFesAsDuWDEXHKOZ9/TSpikA1fOU91vGVjk5
# bTnEtDDCptdhyWJtcrYVMIWZXPpuyNXjLwTPuNS1B44kYbgK2VFeZLxrQh2vp9XT
# atOWxrEScOl2I6xNbVG4d1dTUALFnHo8Ww6UIDyu+lKsQi7gecm80JjVwV+NErU=
# SIG # End signature block


















