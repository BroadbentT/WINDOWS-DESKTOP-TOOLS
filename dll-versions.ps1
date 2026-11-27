# Set the path to the directory you want to scan
$directoryPath = "C:\Users\terencebroadbent\AppData\Roaming\BigHand\BigHand Hub\Attachments\Addins\iManage\"

# Get all .dll files in the directory (non-recursive)
$dllFiles = Get-ChildItem -Path $directoryPath -Filter *.dll -File

# Create an empty array to store results
$results = @()

foreach ($file in $dllFiles) {
    $versionInfo = $file.VersionInfo

    $results += [PSCustomObject]@{
        FileName     = $file.Name
#        FullPath     = $file.FullName
        FileVersion  = $versionInfo.FileVersion
#        ProductVersion = $versionInfo.ProductVersion
    }
}

# Output results to the console
$results | Format-Table -AutoSize

# Optional: Export to CSV
# $results | Export-Csv -Path "C:\Path\To\DllVersions.csv" -NoTypeInformation 