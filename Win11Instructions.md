# Installing Windows 11: On a personal home computer
## This is written by David J Drosdick

# Getting PowerShell to Work 
- Open PowerShell, as Administrator
    - It’ll be Windows PowerShell 
    - It will be slow

***Run the following commands*** <br>
**DISCLAIMER THIS ALLOWS ***whatever bullshit*** scripts I** <br>
***OR ANYONE THAT GETS ACCESS TO YOUR TERMINAL THINGS ARE GOOD TO RUN*** <br>
**This can be a security liablity depending on steps taken to secure your environment.** <br>
**Most personal computers are not secure. You should rerestrict**<br>

    ``` 
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force -Scope Machine
    ``` 
- Install Powershell 7:
    - Direct Link: [PowerShell-7.5.2-win-x64.msi](https://github.com/PowerShell/PowerShell/releases/download/v7.5.2/PowerShell-7.5.2-win-x64.msi)
    - PowerShell Method: Copy and paste into your PowerShell window as a full command block. It might not work properly line by line
    ```
    if ($psVersionTable.PSVersion.Major -ne 7){
    Write-Output "Installing PowerShell 7"
    ## Using Invoke-RestMethod
    $webData = Invoke-RestMethod -Uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest"
    ## Using Invoke-WebRequest
    $webData = ConvertFrom-JSON (Invoke-WebRequest -uri "https://api.github.com/repos/PowerShell/PowerShell/releases/latest")
    ## The release download information is stored in the "assets" section of the data
    $assets = $webData.assets
    ## The pipeline is used to filter the assets object to find the release version we want
    $asset = $assets | where-object { $_.name -match "win-x64" -and $_.name -match ".msi"}
    ## Download the latest version into the same directory we are running the script in
    write-output "Downloading $($asset.name)"
    Invoke-WebRequest $asset.browser_download_url -OutFile "$pwd\$($asset.name)"
    msiexec.exe /package PowerShell-7.5.0-win-x64.msi /quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1 ADD_PATH=1
    Write-Output "Install of PowerShell 7 Completed, relaunch and rerun with PWSH 7"
    }
    ```
- If Provided the ZIP File, exected the 'ProvidedModule' into C:\Program Files\PowerShell\Modules
- Launch PowerShell 7 as Admin:
    ```
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
    ```
- Review the email I sent for specific commands as this will handle installing the module

- When concluded:
```
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope Machine
```



