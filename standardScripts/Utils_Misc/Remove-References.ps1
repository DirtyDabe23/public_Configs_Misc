# Define your root path
$rootPath = "C:\ISO\Container"

# Gather all items recursively
$files = Get-ChildItem -Path $rootPath -Recurse -Force

# Sort items deepest path first (safe for renaming folders)
$files = $files | Sort-Object { $_.FullName.Split('\').Count } -Descending

$filesModified = @()

# Function to handle replacements
function Replace-NamesAndContent {
    param (
        [array]$replacements,
        [string]$valueType
    )

    foreach ($replacement in $replacements) {
        $pattern = $replacement.oldName
        $replacementValue = $replacement.anonName

        foreach ($item in $files) {
            # Replace in file contents
            if (-not $item.PSIsContainer) {
                $content = Get-Content -Path $item.FullName -Raw
                if ($content -match [regex]::Escape($pattern)) {
                    $content -replace [regex]::Escape($pattern), $replacementValue | Set-Content -Path $item.FullName -Force
                    $filesModified += [PSCustomObject]@{
                        File        = $item.FullName
                        FileNewName = "N/A"
                        operation   = "File Content Replacement"
                        valueType   = $valueType
                    }
                }
            }

            # Replace in names
            if ($item.Name -match [regex]::Escape($pattern)) {
                $newName = $item.Name -replace [regex]::Escape($pattern), $replacementValue
                $newFullPath = Join-Path -Path $item.DirectoryName -ChildPath $newName
                Rename-Item -LiteralPath $item.FullName -NewName $newName

                $filesModified += [PSCustomObject]@{
                    File        = $item.FullName
                    FileNewName = $newName
                    operation   = $item.PSIsContainer ? "Folder Name Replacement" : "File Name Replacement"
                    valueType   = $valueType
                }

                # Refresh the reference
                $item = Get-Item -LiteralPath $newFullPath
            }
        }
    }
}

# Run replacements for both types
Replace-NamesAndContent -replacements $removedCompanyNameKey -valueType "Company"
Replace-NamesAndContent -replacements $removedOfficeLocationKey -valueType "Office"

# Optional: output results
$filesModified | Format-Table -AutoSize


