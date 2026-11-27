<#
.SYNOPSIS
    .NET Desktop Application Inspection Script

.DESCRIPTION
    Determines:
      - Whether an application is a .NET executable
      - Target Framework (if present)
      - CLR Runtime Version
      - Installed .NET Framework version
      - Loaded CLR (if the application is running)
      - General assessment comments

.EXAMPLE
    .\Get-DotNetApplicationInfo.ps1 -Path "C:\Program Files\Vendor\App.exe"

.EXAMPLE
    .\Get-DotNetApplicationInfo.ps1 -Path "C:\Program Files\Vendor\App.exe" `
        -ListDlls "C:\Tools\Sysinternals\listdlls.exe"
#>

param(
    [Parameter(Mandatory)]
    [string]$Path,

    [string]$ListDlls
)

Write-Host ""
Write-Host "======================================================="
Write-Host "        .NET Desktop Application Assessment"
Write-Host "======================================================="

if (!(Test-Path $Path))
{
    Write-Host "Application not found."
    exit
}

Write-Host ""
Write-Host "Application:"
Write-Host " $Path"

Write-Host ""
Write-Host "-------------------------------------------------------"
Write-Host "Assembly Information"
Write-Host "-------------------------------------------------------"

try
{
    $asm = [Reflection.Assembly]::ReflectionOnlyLoadFrom($Path)

    Write-Host ("Image Runtime Version : {0}" -f $asm.ImageRuntimeVersion)

}
catch
{
    Write-Host "Not a managed (.NET) executable."
    exit
}

Write-Host ""

try
{
    Add-Type -AssemblyName System.Runtime

    $framework = [Reflection.Assembly]::LoadFile($Path).
        GetCustomAttributes(
            [System.Runtime.Versioning.TargetFrameworkAttribute],
            $false
        )

    if($framework.Count -gt 0)
    {
        Write-Host ("Target Framework     : {0}" -f $framework[0].FrameworkName)
    }
    else
    {
        Write-Host "Target Framework     : Not embedded"
    }
}
catch
{
    Write-Host "Target Framework     : Unable to determine"
}

Write-Host ""
Write-Host "-------------------------------------------------------"
Write-Host ".NET Framework Installed"
Write-Host "-------------------------------------------------------"

try
{
    $release = (Get-ItemProperty `
        'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release

    $version = switch ($release)
    {
        {$_ -ge 533320} {"4.8.1"}
        {$_ -ge 528040} {"4.8"}
        {$_ -ge 461808} {"4.7.2"}
        {$_ -ge 461308} {"4.7.1"}
        {$_ -ge 460798} {"4.7"}
        default {"Older"}
    }

    Write-Host "Installed Version    : $version"
    Write-Host "Release              : $release"
}
catch
{
    Write-Host "Unable to determine installed version."
}

Write-Host ""

$proc = Get-Process |
    Where-Object { $_.Path -eq $Path } |
    Select-Object -First 1

if($proc)
{
    Write-Host "-------------------------------------------------------"
    Write-Host "Running Process"
    Write-Host "-------------------------------------------------------"

    Write-Host "Process Name         : $($proc.ProcessName)"
    Write-Host "PID                  : $($proc.Id)"

    if($ListDlls -and (Test-Path $ListDlls))
    {
        Write-Host ""
        Write-Host "Loaded CLR"

        & $ListDlls $proc.Id |
            Select-String "clr.dll|mscoreei.dll"
    }
}
else
{
    Write-Host "Application is not currently running."
}

Write-Host ""
Write-Host "-------------------------------------------------------"
Write-Host "Assessment Summary"
Write-Host "-------------------------------------------------------"

$tf = if($framework.Count -gt 0)
{
    $framework[0].FrameworkName
}
else
{
    "Unknown (.NET Framework 4.x runtime)"
}

Write-Host @"

Application Type
----------------
Managed Microsoft .NET application.

Target Framework
----------------
$tf

CLR Runtime
-----------
$($asm.ImageRuntimeVersion)

Installed Runtime
-----------------
Microsoft .NET Framework $version (Release $release)

Assessment Notes
----------------
• The application targets the .NET Framework runtime.
• .NET Framework is in servicing mode and receives security and reliability
  updates only.
• Microsoft recommends modern .NET (e.g. .NET 8+) for new application
  development.
• Targeting an older .NET Framework version does not necessarily represent a
  security vulnerability, provided the underlying Windows installation remains
  fully patched.

"@