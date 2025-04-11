function Start-BetterMessageTrace {
    <#
    .SYNOPSIS
    This function performs a message trace based on a provided mailbox identity.  
    
    .DESCRIPTION
    This function performs a message trace based on the provided mailbox identity as a sender.
    It will search for all event types that correspond with a failure, run the command to pull all events that match the following
    EventType: Failed , Pending , FilteredAsSpam
    
    .EXAMPLE
    Start-BetterMessageTrace -senderAddress givenName.surName@domain.com 

    
    .NOTES
    This module is most performant on PowerShell 5.1.2
    It requires ExchangeOnlineManagement and the requisite permissions to perform message traces.
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory,Position=0,HelpMessage="Enter an identity that would be used for -senderAddress in get-messagetrace -senderaddress")]
        [string]
        $senderAddress
    )
    $messageTraceLogger     =   @()
    $continue               =   $true
    while($continue){
        $messageTraceInfo   =   @()
        $failedMessages     =   Get-MessageTrace -senderAddress $senderAddress -status Failed , Pending , FilteredAsSpam
        forEach($failedMessage in $failedMessages){
            $messageDetail          =   $failedMessage | Get-MessageTraceDetail | Where-Object {($_.Event -in @("Fail","Drop","Spam"))} | Select-Object -Property *
            $messageTraceInfo       +=  [PSCustomObject]@{
                senderAddress       =   $failedMessage.senderAddress
                recipientAddress    =   $failedMessage.recipientAddress
                reasonFailed        =   $messageDetail.Detail
            }
        }
        $now = Get-Date -Format "HH:mm"
        $messageTraceLogger         =   [PSCustomObject]@{
            Time                    =   $now
            traceData               =   $messageTraceInfo
        }
        Write-Output                    "Press R to Rerun`nPress S for New Sender`nPress E, or any other key, to Exit"
        $response           =   $host.UI.RawUI.readKey("noEcho,IncludeKeyDown")
        switch ($response.key){
            'R'{Out-Null}
            'S'{$senderAddress = Read-Host "Enter an identity that would be used for -senderAddress in get-messagetrace -senderaddress"}
            Default {return $messageTraceLogger}
        }
    }
}