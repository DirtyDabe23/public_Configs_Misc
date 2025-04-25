$pattern = Read-Host "Enter the string pattern to search"
$replacementValue = Read-Host "Enter the value to set as the replacement"
$files = Get-ChildItem -Path .\* -Recurse | select-string -Pattern $pattern | Select-Object -ExpandProperty Path -Unique
ForEach ($file in $files){
    (Get-Content -Path $file -Raw) -replace "$pattern" , $replacementValue | Set-Content -Path $file -Force
}

$vaultName = Read-Host "Enter the Vault Name" 
$keys = Get-AzKeyVaultSecret -VaultName $vaultName 
#The following is useful for removing all secured keys from script(s)
$filesModified = @()
ForEach ($keyVaultKey in $keys){
    $pattern = Get-AzKeyVaultSecret -VaultName $vaultName -Name $keyVaultKey.Name -AsPlainText
    $replacementValue = '$', $keyVaultKey.Name -join ""
    $files = Get-ChildItem -Path .\* -Recurse | select-string -Pattern $pattern | Select-Object -ExpandProperty Path -Unique
    ForEach ($file in $files){
        (Get-Content -Path $file -Raw) -replace "$pattern" , $replacementValue | Set-Content -Path $file -Force
         $filesModified += [PSCustomObject]@{
            FileModified = $file
        }
    }
}


