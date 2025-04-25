$filesModified = @()
ForEach ($file in $files){
    $content = Get-Content -Path $file -Raw
    #First Check Contents for Company Name
    ForEach ($companyValue in $removedCompanyNameKey){
        if ($content -match $companyValue.oldName){
            $content -replace $companyValue.oldName , $badValues.anonName | Set-Content -Path $file -Force
            $filesModified += [PSCustomObject]@{
                File            = $file.FullName
                FileNewName     = "N/A"
                operation       = "File Content Replacement"
                valueType       = "Company"
            }
        }
    }
    ForEach ($officeValue in $removedOfficeLocationKey){
        if ($content -match $officeValue.oldName){
            $content -replace $companyValue.oldName , $badValues.anonName | Set-Content -Path $file -Force
            $filesModified += [PSCustomObject]@{
                File            = $file.FullName
                FileNewName     = "N/A"
                operation       = "File Content Replacement"
                valueType       = "Office"
            }
        }
    }
    #Then Check Contents for Office Location Name

    #Then rename file if matches Office Locations
        #Refetch name
    #Then rename file if it matches Company Name
    
    #itemize all changes.
}

