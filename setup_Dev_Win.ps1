if ($PsVersionTAble.PSVersion.Major -ne 7){
    Write-Output "You need to do this in PowerShell 7. Install that manually or use your other script"
    exit
}
else{
        $totalAsks = 0
        $response = Read-Host "Enter 'I Agree' exactly as it appears between both single quotes, to agree that you understand you're installing Dave's Dev Config at your own discretion, and it's assumed you got approval, AKA, this isn't the fault of the author."
        while ($response -cne 'I Agree' -and ($totalAsks -lt 2)){
            $response = Read-Host "Try Again"
            $totalAsks++
        }
        if ($totalAsks -gt 2){
            Write-Output "Not trusted."
            Exit 1
        }
    If (!((Get-PSRepository -Name PSGAllery | Select-Object -Property InstallationPolicy) -eq "Trusted")){Set-PSResourceRepository -Name PSGallery -Trusted:$true}
    if(!(Get-AppXPackage -name Microsoft.DesktopAppInstaller)){Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe}
    if (!(Get-PackageProvider -Name PowerShellGet)){Install-PackageProvider WinGet -Force}
    If (!(Get-PSResource -Name PSWinGet -Scope AllUsers -erroraction silentlyContinue)){Install-PSResource -Name PSWinGet -Scope AllUsers}
    $wingetPackages = Get-WingetPackage 
    $devProgs = Invoke-RestMethod -Method Get -uri 'https://raw.githubusercontent.com/DirtyDabe23/DDrosdick_Public_Repo/refs/heads/main/devProgs.json'
    forEach ($devProg in $devProgs.Sources.Packages.PackageIdentifier){if ($devProg -notin $wingetPackages.id){winget install --id $devProg --accept-source-agreements --accept-package-agreements --silent --force}}
    $reqExtensions = @("github.codespaces",`
    "github.vscode-pull-request-github",`
    "dillonchanis.midnight-city",`
    "ms-python.debugpy",`
    "ms-python.python",`
    "ms-python.python",`
    "ms-python.python",`
    "ms-python.python",`
    "ms-python.vscode-pylance",`
    "ms-toolsai.jupyter",`
    "ms-toolsai.jupyter-keymap",`
    "ms-toolsai.jupyter-renderers",`
    "ms-toolsai.vscode-jupyter-cell-tags",`
    "ms-toolsai.vscode-jupyter-slideshow",`
    "ms-vscode-remote.remote-wsl",`
    "ms-vscode.notepadplusplus-keybindings",`
    "ms-vscode.powershell",`
    "ms-vscode.vscode-github-issue-notebooks")
    $currentExtensions = code --list-extensions
    ForEach($reqExtension in $reqExtensions){if ($reqExtension -notin $currentExtensions){code --install-extension $reqExtension}}
    oh-my-posh font install JetBrainsMono
    oh-my-posh config -c .\OhMyPoshConfig.JSON
    $terminalSettings = Invoke-RestMethod -Method Get -URI 
    set-content -Path "$env:LOCALAPPDATA\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json" -Value $terminalSettings

    $modules = Invoke-RestMethod -Method Get -URI "https://raw.githubusercontent.com/DirtyDabe23/DDrosdick_Public_Repo/refs/heads/main/PSModules.JSON"
    ForEach ($module in $modules){
        Install-PSREsource -Name $module.name -Version $module.version -Scope AllUsers -TrustRepository:$true -Repository $module.Repository
    }
}