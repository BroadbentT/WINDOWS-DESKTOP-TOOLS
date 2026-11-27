# ============================================================
#
# Certificate Validation & Trust Assessment
# Generic EXE Assessment
#
# PowerShell 5.1 compatible
#
# ============================================================
#
# The script:
#
# 1. Checks Authenticode signature
# 2. Displays signing certificate details
# 3. Checks certificate validity
# 4. Checks Windows certificate stores
# 5. Discovers HTTPS endpoints from application files
# 6. Performs live TLS endpoint checks
# 7. Searches configuration files for TLS indicators
# 8. Searches executable strings for TLS indicators
# 9. Searches for certificate/private-key indicators
# 10. Performs safe runtime TLS policy observations
# 11. Optionally launches the application for passive observation
# 12. Performs detailed 60-second runtime observation
# 13. Records PID and process information
# 14. Records TCP connections associated with the PID
# 15. Saves complete assessment locally
# 16. Saves structured CSV runtime observations
# 17. Saves structured CSV findings
#
# IMPORTANT:
#
# Static analysis cannot prove runtime certificate behaviour.
#
# This script does NOT:
#
# - install certificates
# - install a CA
# - modify Windows certificate stores
# - modify proxy settings
# - modify the hosts file
# - modify the EXE
# - modify application configuration
# - inject code into the application
#
# Controlled runtime testing is still required to definitively
# establish:
#
# - expired certificate rejection
# - self-signed certificate rejection
# - unexpected CA rejection
# - user-installed CA behaviour
# - certificate pinning
# - public-key pinning
# - validation bypass
# - application behaviour after TLS failure
#
# ============================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

Clear-Host

# ============================================================
# GLOBAL VARIABLES
# ============================================================

$script:AssessmentStarted = Get-Date
$script:OutputFile = $null
$script:RuntimeObservationFile = $null
$script:FindingsFile = $null

$script:Findings = New-Object System.Collections.ArrayList
$script:RuntimeObservations = New-Object System.Collections.ArrayList

# ============================================================
# LOGGING
# ============================================================

function Write-Result {
    param(
        [AllowEmptyString()]
        [string]$Message = "",

        [ConsoleColor]$Color = [ConsoleColor]::White
    )

    if ([string]::IsNullOrEmpty($Message)) {
        Write-Host ""
    }
    else {
        Write-Host $Message -ForegroundColor $Color
    }

    if ($script:OutputFile) {
        try {
            Add-Content `
                -LiteralPath $script:OutputFile `
                -Value $Message `
                -ErrorAction SilentlyContinue
        }
        catch {
            # Logging failure must never stop the assessment.
        }
    }
}

function Add-Finding {
    param(
        [string]$Category,
        [string]$Status,
        [string]$Description,
        [string]$Evidence = ""
    )

    try {
        [void]$script:Findings.Add(
            [PSCustomObject]@{
                Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Category    = $Category
                Status      = $Status
                Description = $Description
                Evidence    = $Evidence
            }
        )
    }
    catch {
        # Continue if structured logging fails.
    }
}

function Write-Pass {
    param(
        [AllowEmptyString()]
        [string]$Message = ""
    )

    if ([string]::IsNullOrEmpty($Message)) {
        Write-Result ""
    }
    else {
        Write-Result "[PASS] $Message" Green
        Add-Finding `
            -Category "Assessment" `
            -Status "PASS" `
            -Description $Message
    }
}

function Write-Fail {
    param(
        [AllowEmptyString()]
        [string]$Message = ""
    )

    if ([string]::IsNullOrEmpty($Message)) {
        Write-Result ""
    }
    else {
        Write-Result "[FAIL] $Message" Red
        Add-Finding `
            -Category "Assessment" `
            -Status "FAIL" `
            -Description $Message
    }
}

function Write-Review {
    param(
        [AllowEmptyString()]
        [string]$Message = ""
    )

    if ([string]::IsNullOrEmpty($Message)) {
        Write-Result ""
    }
    else {
        Write-Result "[REVIEW] $Message" Yellow
        Add-Finding `
            -Category "Assessment" `
            -Status "REVIEW" `
            -Description $Message
    }
}

function Write-Manual {
    param(
        [AllowEmptyString()]
        [string]$Message = ""
    )

    if ([string]::IsNullOrEmpty($Message)) {
        Write-Result ""
    }
    else {
        Write-Result "[MANUAL] $Message" Magenta
        Add-Finding `
            -Category "Manual Testing Required" `
            -Status "NOT ESTABLISHED" `
            -Description $Message
    }
}

function Write-NotEstablished {
    param(
        [AllowEmptyString()]
        [string]$Message = ""
    )

    if ([string]::IsNullOrEmpty($Message)) {
        Write-Result ""
    }
    else {
        Write-Result "[NOT ESTABLISHED] $Message" Yellow
        Add-Finding `
            -Category "Assessment" `
            -Status "NOT ESTABLISHED" `
            -Description $Message
    }
}

function Write-NoStaticEvidence {
    param(
        [AllowEmptyString()]
        [string]$Message = ""
    )

    if ([string]::IsNullOrEmpty($Message)) {
        Write-Result ""
    }
    else {
        Write-Result "[NO STATIC EVIDENCE] $Message" DarkYellow
        Add-Finding `
            -Category "Static Analysis" `
            -Status "NO STATIC EVIDENCE" `
            -Description $Message
    }
}

# ============================================================
# NORMALIZE THUMBPRINT
# ============================================================

function Normalize-Thumbprint {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ""
    }

    return (
        $Value.Replace(" ", "").
        Replace(":", "").
        Replace("-", "").
        Trim()
    ).ToUpperInvariant()
}

# ============================================================
# GET APPLICATION FILES
# ============================================================

function Get-ApplicationFiles {
    param(
        [Parameter(Mandatory)]
        [string]$ExecutablePath
    )

    $files = @()

    $files += $ExecutablePath

    $directory = Split-Path -Parent $ExecutablePath

    if (
        -not [string]::IsNullOrWhiteSpace($directory) -and
        (Test-Path -LiteralPath $directory)
    ) {

        $additionalFiles = @(
            Get-ChildItem `
                -LiteralPath $directory `
                -File `
                -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Extension.ToLowerInvariant() -in @(
                    ".config",
                    ".json",
                    ".xml",
                    ".ini",
                    ".txt"
                )
            } |
            ForEach-Object {
                $_.FullName
            }
        )

        $files += $additionalFiles
    }

    return @(
        $files |
        Sort-Object -Unique
    )
}

# ============================================================
# EXTRACT HTTPS ENDPOINTS
# ============================================================

function Get-HttpsEndpoints {
    param(
        [Parameter(Mandatory)]
        [string[]]$Files
    )

    $endpoints = @()

    foreach ($file in $Files) {

        if (-not (Test-Path -LiteralPath $file)) {
            continue
        }

        try {

            $extension =
                [System.IO.Path]::GetExtension($file).ToLowerInvariant()

            if ($extension -ne ".exe") {

                $content =
                    Get-Content `
                        -LiteralPath $file `
                        -Raw `
                        -ErrorAction Stop

                $urlMatches = @(
                    [regex]::Matches(
                        $content,
                        '(?i)https://([a-zA-Z0-9][a-zA-Z0-9\.-]+)(?::(\d+))?'
                    )
                )

                foreach ($match in $urlMatches) {

                    $endpointHost =
                        $match.Groups[1].Value

                    $endpointPort =
                        $match.Groups[2].Value

                    if (
                        -not [string]::IsNullOrWhiteSpace(
                            $endpointHost
                        )
                    ) {

                        if (
                            [string]::IsNullOrWhiteSpace(
                                $endpointPort
                            )
                        ) {
                            $endpoints +=
                                "$endpointHost`:443"
                        }
                        else {
                            $endpoints +=
                                "$endpointHost`:$endpointPort"
                        }
                    }
                }
            }
            else {

                $exeStrings =
                    @(Get-ExecutableStrings `
                        -ExecutablePath $file)

                foreach ($stringValue in $exeStrings) {

                    $urlMatches = @(
                        [regex]::Matches(
                            $stringValue,
                            '(?i)https://([a-zA-Z0-9][a-zA-Z0-9\.-]+)(?::(\d+))?'
                        )
                    )

                    foreach ($match in $urlMatches) {

                        $endpointHost =
                            $match.Groups[1].Value

                        $endpointPort =
                            $match.Groups[2].Value

                        if (
                            -not [string]::IsNullOrWhiteSpace(
                                $endpointHost
                            )
                        ) {

                            if (
                                [string]::IsNullOrWhiteSpace(
                                    $endpointPort
                                )
                            ) {
                                $endpoints +=
                                    "$endpointHost`:443"
                            }
                            else {
                                $endpoints +=
                                    "$endpointHost`:$endpointPort"
                            }
                        }
                    }
                }
            }
        }
        catch {
            # Continue with remaining files.
        }
    }

    return @(
        $endpoints |
        Sort-Object -Unique
    )
}

# ============================================================
# STATIC TLS INDICATOR SCANNER
# ============================================================

function Find-TlsIndicators {
    param(
        [Parameter(Mandatory)]
        [string[]]$Files
    )

    $patterns = @(
        "RemoteCertificateValidationCallback",
        "ServerCertificateCustomValidationCallback",
        "DangerousAcceptAnyServerCertificateValidator",
        "CertificateValidation",
        "CertificateValidator",
        "CertificateValidationCallback",
        "SslStream",
        "ServicePointManager.ServerCertificateValidationCallback",
        "CheckCertificateRevocationList",
        "HttpClientHandler",
        "WebRequestHandler",
        "X509Chain",
        "X509Certificate2",
        "GetCertHash",
        "GetCertHashString",
        "CertificatePin",
        "CertificatePinning",
        "PinnedCertificate",
        "PinnedCertificates",
        "PublicKeyPin",
        "PublicKeyPinning",
        "PinnedPublicKey",
        "PinningValidator",
        "IgnoreCertificate",
        "IgnoreSsl",
        "BypassCertificate",
        "BypassSsl",
        "AcceptAnyCertificate",
        "TrustAllCertificates",
        "AllowInvalidCertificate",
        "ValidateCertificate"
    )

    $results = @()

    foreach ($file in $Files) {

        if (-not (Test-Path -LiteralPath $file)) {
            continue
        }

        $extension =
            [System.IO.Path]::GetExtension($file).ToLowerInvariant()

        if ($extension -eq ".exe") {
            continue
        }

        try {

            $lines = @(
                Get-Content `
                    -LiteralPath $file `
                    -ErrorAction Stop
            )

            $lineNumber = 0

            foreach ($line in $lines) {

                $lineNumber++

                foreach ($pattern in $patterns) {

                    if (
                        $line -match
                        [regex]::Escape($pattern)
                    ) {

                        $results +=
                            [PSCustomObject]@{
                                File      = $file
                                Line      = $lineNumber
                                Indicator = $pattern
                                Text      = $line.Trim()
                            }

                        break
                    }
                }
            }
        }
        catch {
            # Continue.
        }
    }

    return @($results)
}

# ============================================================
# EXECUTABLE STRINGS
# ============================================================

function Get-ExecutableStrings {
    param(
        [Parameter(Mandatory)]
        [string]$ExecutablePath
    )

    $strings = @()

    try {

        $bytes =
            [System.IO.File]::ReadAllBytes(
                $ExecutablePath
            )

        $asciiBuilder =
            New-Object System.Text.StringBuilder

        foreach ($byte in $bytes) {

            if (
                $byte -ge 32 -and
                $byte -le 126
            ) {

                [void]$asciiBuilder.Append(
                    [char]$byte
                )
            }
            else {

                if ($asciiBuilder.Length -ge 5) {

                    $strings +=
                        $asciiBuilder.ToString()
                }

                [void]$asciiBuilder.Clear()
            }
        }

        if ($asciiBuilder.Length -ge 5) {

            $strings +=
                $asciiBuilder.ToString()
        }
    }
    catch {

        Write-Review `
            "Unable to extract executable strings."
    }

    return @(
        $strings |
        Sort-Object -Unique
    )
}

# ============================================================
# EXECUTABLE TLS INDICATORS
# ============================================================

function Find-ExecutableIndicators {
    param(
        [Parameter(Mandatory)]
        [string]$ExecutablePath
    )

    $patterns = @(
        "RemoteCertificateValidationCallback",
        "ServerCertificateCustomValidationCallback",
        "DangerousAcceptAnyServerCertificateValidator",
        "CertificateValidationCallback",
        "CertificatePinning",
        "PinnedCertificate",
        "PinnedCertificates",
        "PublicKeyPin",
        "PublicKeyPinning",
        "PinnedPublicKey",
        "PinningValidator",
        "IgnoreCertificate",
        "IgnoreSsl",
        "BypassCertificate",
        "BypassSsl",
        "AcceptAnyCertificate",
        "TrustAllCertificates",
        "AllowInvalidCertificate",
        "ServicePointManager",
        "CheckCertificateRevocationList",
        "SslStream",
        "X509Chain",
        "X509Certificate2",
        "GetCertHash",
        "GetCertHashString"
    )

    $strings =
        @(Get-ExecutableStrings `
            -ExecutablePath $ExecutablePath)

    $results = @()

    foreach ($stringValue in $strings) {

        foreach ($pattern in $patterns) {

            if (
                $stringValue -match
                [regex]::Escape($pattern)
            ) {

                $results +=
                    [PSCustomObject]@{
                        File      = $ExecutablePath
                        Indicator = $pattern
                        String    = $stringValue
                    }

                break
            }
        }
    }

    return @(
        $results |
        Sort-Object Indicator, String -Unique
    )
}

# ============================================================
# CERTIFICATE / PRIVATE KEY INDICATORS
# ============================================================

function Find-CertificateKeyIndicators {
    param(
        [Parameter(Mandatory)]
        [string[]]$Files
    )

    $patterns = @(
        "BEGIN CERTIFICATE",
        "BEGIN X509 CERTIFICATE",
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        ".pfx",
        ".p12",
        ".pem",
        ".crt",
        ".cer"
    )

    $results = @()

    foreach ($file in $Files) {

        if (-not (Test-Path -LiteralPath $file)) {
            continue
        }

        $extension =
            [System.IO.Path]::GetExtension($file).ToLowerInvariant()

        if ($extension -eq ".exe") {
            continue
        }

        try {

            $content =
                Get-Content `
                    -LiteralPath $file `
                    -Raw `
                    -ErrorAction Stop

            foreach ($pattern in $patterns) {

                if (
                    $content -match
                    [regex]::Escape($pattern)
                ) {

                    $results +=
                        [PSCustomObject]@{
                            File      = $file
                            Indicator = $pattern
                        }
                }
            }
        }
        catch {
            # Continue.
        }
    }

    return @(
        $results |
        Sort-Object File, Indicator -Unique
    )
}

# ============================================================
# LIVE TLS ENDPOINT TEST
# ============================================================

function Test-TlsEndpoint {
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint
    )

    $endpointHost = $Endpoint
    $endpointPort = 443

    if ($Endpoint -match '^(.+):(\d+)$') {

        $endpointHost =
            $Matches[1]

        $endpointPort =
            [int]$Matches[2]
    }

    Write-Result ""
    Write-Result "============================================================" Cyan
    Write-Result " LIVE TLS ENDPOINT" Cyan
    Write-Result "============================================================" Cyan
    Write-Result "Testing: $endpointHost`:$endpointPort"

    $tcpClient = $null
    $sslStream = $null
    $remoteCertificate = $null
    $chain = $null

    try {

        $tcpClient =
            New-Object System.Net.Sockets.TcpClient

        $task =
            $tcpClient.ConnectAsync(
                $endpointHost,
                $endpointPort
            )

        if (-not $task.Wait(10000)) {

            Write-Fail `
                "TCP connection timed out."

            return
        }

        if (-not $tcpClient.Connected) {

            Write-Fail `
                "TCP connection failed."

            return
        }

        Write-Pass `
            "TCP connection established."

        # Intentionally accept the certificate so it can be
        # inspected. This is NOT an application validation test.

        $sslStream =
            New-Object System.Net.Security.SslStream(
                $tcpClient.GetStream(),
                $false,
                {
                    param(
                        $sender,
                        $certificate,
                        $certificateChain,
                        $sslPolicyErrors
                    )

                    return $true
                }
            )

        $sslStream.AuthenticateAsClient(
            $endpointHost
        )

        if ($null -eq $sslStream.RemoteCertificate) {

            Write-Fail `
                "Remote server did not provide a certificate."

            return
        }

        $remoteCertificate =
            New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                $sslStream.RemoteCertificate
            )

        Write-Result ""
        Write-Result "Remote Certificate" White

        Write-Result `
            "Subject          : $($remoteCertificate.Subject)"

        Write-Result `
            "Issuer           : $($remoteCertificate.Issuer)"

        Write-Result `
            "Thumbprint       : $($remoteCertificate.Thumbprint)"

        Write-Result `
            "Serial Number    : $($remoteCertificate.SerialNumber)"

        Write-Result `
            "Valid From       : $($remoteCertificate.NotBefore)"

        Write-Result `
            "Valid Until      : $($remoteCertificate.NotAfter)"

        Write-Result `
            "Signature Algo   : $($remoteCertificate.SignatureAlgorithm.FriendlyName)"

        $now = Get-Date

        if (
            $remoteCertificate.NotBefore -le $now -and
            $remoteCertificate.NotAfter -ge $now
        ) {

            Write-Pass `
                "Remote certificate is currently valid."
        }
        else {

            Write-Fail `
                "Remote certificate is expired or not yet valid."
        }

        $chain =
            New-Object System.Security.Cryptography.X509Certificates.X509Chain

        $chain.ChainPolicy.RevocationMode =
            [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck

        $chainBuilt =
            $chain.Build(
                $remoteCertificate
            )

        if ($chainBuilt) {

            Write-Pass `
                "Windows successfully built the remote certificate chain."
        }
        else {

            Write-Fail `
                "Windows could not build the remote certificate chain."

            foreach ($status in $chain.ChainStatus) {

                Write-Result `
                    "  $($status.Status): $($status.StatusInformation.Trim())"
            }
        }

        Write-Result ""
        Write-Result "Certificate Chain:" White

        foreach ($element in $chain.ChainElements) {

            Write-Result ""

            Write-Result `
                "Subject : $($element.Certificate.Subject)"

            Write-Result `
                "Issuer  : $($element.Certificate.Issuer)"

            Write-Result `
                "SHA1    : $($element.Certificate.Thumbprint)"
        }

        Write-Result ""
        Write-Result "Certificate Baseline Information" White
        Write-Result ""
        Write-Result "Observed SHA-1 thumbprint:"
        Write-Result $remoteCertificate.Thumbprint

        Write-Review `
            "No expected certificate thumbprint is hard-coded; observed values can be used for an authorised baseline."
    }
    catch {

        $reason = $_.Exception.Message

        if ([string]::IsNullOrWhiteSpace($reason)) {
            $reason = "Unknown TLS connection error."
        }

        Write-Fail `
            "TLS connection failed."

        Write-Result `
            "Reason: $reason"
    }
    finally {

        if ($sslStream) {
            $sslStream.Dispose()
        }

        if ($tcpClient) {
            $tcpClient.Dispose()
        }
    }
}

# ============================================================
# SAFE RUNTIME TLS POLICY TESTS
# ============================================================

function Test-RuntimeTlsPolicy {
    param(
        [Parameter(Mandatory)]
        [string]$Endpoint,

        [Parameter(Mandatory)]
        [string]$ExecutablePath,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [object[]]$ExecutableFindings = @(),

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [object[]]$KeyFindings = @()
    )

    # Always normalize collections.
    $ExecutableFindings = @($ExecutableFindings)
    $KeyFindings = @($KeyFindings)

    $endpointHost = $Endpoint
    $endpointPort = 443

    if ($Endpoint -match '^(.+):(\d+)$') {

        $endpointHost =
            $Matches[1]

        $endpointPort =
            [int]$Matches[2]
    }

    Write-Result ""
    Write-Result "============================================================" Cyan
    Write-Result " SAFE RUNTIME TLS POLICY TESTS" Cyan
    Write-Result "============================================================" Cyan
    Write-Result "Endpoint: $endpointHost`:$endpointPort"

    # --------------------------------------------------------
    # TEST 1
    # Normal hostname / certificate validation
    # --------------------------------------------------------

    Write-Result ""
    Write-Result "[TEST] Normal hostname and certificate validation"

    $normalTcp = $null
    $normalSsl = $null

    try {

        $normalTcp =
            New-Object System.Net.Sockets.TcpClient

        $connectTask =
            $normalTcp.ConnectAsync(
                $endpointHost,
                $endpointPort
            )

        if (-not $connectTask.Wait(10000)) {

            Write-Fail `
                "Normal TLS connection timed out."
        }
        elseif (-not $normalTcp.Connected) {

            Write-Fail `
                "Normal TCP connection failed."
        }
        else {

            $script:RuntimeSslPolicyErrors = $null

            $normalCallback = {

                param(
                    $sender,
                    $certificate,
                    $certificateChain,
                    $sslPolicyErrors
                )

                $script:RuntimeSslPolicyErrors =
                    $sslPolicyErrors

                return (
                    $sslPolicyErrors -eq
                    [System.Net.Security.SslPolicyErrors]::None
                )
            }

            $normalSsl =
                New-Object System.Net.Security.SslStream(
                    $normalTcp.GetStream(),
                    $false,
                    $normalCallback
                )

            try {

                $normalSsl.AuthenticateAsClient(
                    $endpointHost
                )

                if (
                    $script:RuntimeSslPolicyErrors -eq
                    [System.Net.Security.SslPolicyErrors]::None
                ) {

                    Write-Pass `
                        "Normal hostname/certificate validation succeeded."
                }
                else {

                    Write-Fail `
                        "TLS validation returned: $($script:RuntimeSslPolicyErrors)"
                }
            }
            catch {

                $reason = $_.Exception.Message

                if ([string]::IsNullOrWhiteSpace($reason)) {
                    $reason = "Unknown TLS validation error."
                }

                Write-Fail `
                    "Normal TLS validation rejected the connection: $reason"
            }
        }
    }
    catch {

        $reason = $_.Exception.Message

        if ([string]::IsNullOrWhiteSpace($reason)) {
            $reason = "Unknown runtime TLS error."
        }

        Write-Fail `
            "Normal TLS runtime test failed: $reason"
    }
    finally {

        if ($normalSsl) {
            $normalSsl.Dispose()
        }

        if ($normalTcp) {
            $normalTcp.Dispose()
        }
    }

    # --------------------------------------------------------
    # TEST 2
    # Runtime certificate validity
    # --------------------------------------------------------

    Write-Result ""
    Write-Result "[TEST] Runtime certificate validity"

    $certificateTcp = $null
    $certificateSsl = $null
    $runtimeCertificate = $null

    try {

        $certificateTcp =
            New-Object System.Net.Sockets.TcpClient

        $connectTask =
            $certificateTcp.ConnectAsync(
                $endpointHost,
                $endpointPort
            )

        if (-not $connectTask.Wait(10000)) {
            throw "Connection timed out."
        }

        $certificateSsl =
            New-Object System.Net.Security.SslStream(
                $certificateTcp.GetStream(),
                $false,
                {
                    param(
                        $sender,
                        $certificate,
                        $certificateChain,
                        $sslPolicyErrors
                    )

                    return $true
                }
            )

        $certificateSsl.AuthenticateAsClient(
            $endpointHost
        )

        if ($certificateSsl.RemoteCertificate) {

            $runtimeCertificate =
                New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                    $certificateSsl.RemoteCertificate
                )

            $runtimeNow = Get-Date

            if (
                $runtimeCertificate.NotBefore -le $runtimeNow -and
                $runtimeCertificate.NotAfter -ge $runtimeNow
            ) {

                Write-Pass `
                    "Runtime certificate is currently within its validity period."
            }
            else {

                Write-Fail `
                    "Runtime certificate is expired or not yet valid."
            }

            Write-Result ""
            Write-Result "Runtime certificate:"

            Write-Result `
                "Subject    : $($runtimeCertificate.Subject)"

            Write-Result `
                "Issuer     : $($runtimeCertificate.Issuer)"

            Write-Result `
                "Thumbprint : $($runtimeCertificate.Thumbprint)"

            Write-Result `
                "Valid From : $($runtimeCertificate.NotBefore)"

            Write-Result `
                "Valid Until: $($runtimeCertificate.NotAfter)"
        }
        else {

            Write-Fail `
                "Endpoint did not provide a certificate."
        }
    }
    catch {

        $reason = $_.Exception.Message

        if ([string]::IsNullOrWhiteSpace($reason)) {
            $reason = "Unknown runtime certificate error."
        }

        Write-Fail `
            "Runtime certificate test failed: $reason"
    }
    finally {

        if ($certificateSsl) {
            $certificateSsl.Dispose()
        }

        if ($certificateTcp) {
            $certificateTcp.Dispose()
        }
    }

    # --------------------------------------------------------
    # TEST 3
    # Self-signed certificate assessment
    # --------------------------------------------------------

    Write-Result ""
    Write-Result "[TEST] Self-signed certificate assessment"

    if ($runtimeCertificate) {

        if (
            $runtimeCertificate.Subject -eq
            $runtimeCertificate.Issuer
        ) {

            Write-Review `
                "The observed endpoint certificate appears to be self-signed."
        }
        else {

            Write-Pass `
                "The observed endpoint certificate is not self-signed."
        }
    }
    else {

        Write-Review `
            "Unable to assess whether the endpoint certificate is self-signed."
    }

    # --------------------------------------------------------
    # TEST 4
    # Windows certificate chain
    # --------------------------------------------------------

    Write-Result ""
    Write-Result "[TEST] Runtime Windows certificate-chain validation"

    if ($runtimeCertificate) {

        try {

            $runtimeChain =
                New-Object System.Security.Cryptography.X509Certificates.X509Chain

            $runtimeChain.ChainPolicy.RevocationMode =
                [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck

            $runtimeChainBuilt =
                $runtimeChain.Build(
                    $runtimeCertificate
                )

            if ($runtimeChainBuilt) {

                Write-Pass `
                    "Windows successfully built the runtime certificate chain."
            }
            else {

                Write-Fail `
                    "Windows could not build the runtime certificate chain."

                foreach ($chainStatus in $runtimeChain.ChainStatus) {

                    Write-Result `
                        "  $($chainStatus.Status): $($chainStatus.StatusInformation.Trim())"
                }
            }
        }
        catch {

            $reason = $_.Exception.Message

            if ([string]::IsNullOrWhiteSpace($reason)) {
                $reason = "Unknown chain validation error."
            }

            Write-Fail `
                "Runtime chain validation failed: $reason"
        }
    }
    else {

        Write-Review `
            "Runtime certificate unavailable; chain validation skipped."
    }

    # --------------------------------------------------------
    # TEST 5
    # Static pinning evidence
    # --------------------------------------------------------

    Write-Result ""
    Write-Result "[TEST] Certificate/public-key pinning evidence"

    $pinPatterns = @(
        "CertificatePin",
        "CertificatePinning",
        "PinnedCertificate",
        "PinnedCertificates",
        "PublicKeyPin",
        "PublicKeyPinning",
        "PinnedPublicKey",
        "PinningValidator"
    )

    $pinEvidence = @(
        $ExecutableFindings |
        Where-Object {
            $_.Indicator -in $pinPatterns
        }
    )

    if ($pinEvidence.Count -gt 0) {

        Write-Review `
            "Potential certificate/public-key pinning indicators were found."

        foreach ($finding in $pinEvidence) {

            Write-Result `
                "  Indicator: $($finding.Indicator)"
        }

        Write-Manual `
            "Controlled runtime testing is required to confirm whether pinning is actually enforced."
    }
    else {

        Write-NoStaticEvidence `
            "No explicit certificate/public-key pinning indicator was identified."
    }

    # --------------------------------------------------------
    # TEST 6
    # Custom certificate callback evidence
    # --------------------------------------------------------

    Write-Result ""
    Write-Result "[TEST] Custom certificate-validation callback evidence"

    $callbackPatterns = @(
        "RemoteCertificateValidationCallback",
        "ServerCertificateCustomValidationCallback",
        "CertificateValidationCallback",
        "DangerousAcceptAnyServerCertificateValidator"
    )

    $callbackEvidence = @(
        $ExecutableFindings |
        Where-Object {
            $_.Indicator -in $callbackPatterns
        }
    )

    if ($callbackEvidence.Count -gt 0) {

        Write-Review `
            "Potential custom certificate-validation callback detected."

        foreach ($finding in $callbackEvidence) {

            Write-Result `
                "  Indicator: $($finding.Indicator)"
        }

        Write-Manual `
            "Runtime testing is required to determine what the callback actually permits."
    }
    else {

        Write-NoStaticEvidence `
            "No explicit custom certificate-validation callback indicator identified."
    }

    # --------------------------------------------------------
    # TEST 7
    # Certificate-validation bypass evidence
    # --------------------------------------------------------

    Write-Result ""
    Write-Result "[TEST] Certificate-validation bypass evidence"

    $bypassPatterns = @(
        "DangerousAcceptAnyServerCertificateValidator",
        "IgnoreCertificate",
        "IgnoreSsl",
        "BypassCertificate",
        "BypassSsl",
        "AcceptAnyCertificate",
        "TrustAllCertificates",
        "AllowInvalidCertificate"
    )

    $bypassEvidence = @(
        $ExecutableFindings |
        Where-Object {
            $_.Indicator -in $bypassPatterns
        }
    )

    if ($bypassEvidence.Count -gt 0) {

        Write-Fail `
            "Potential certificate-validation bypass indicator detected."

        foreach ($finding in $bypassEvidence) {

            Write-Result `
                "  Indicator: $($finding.Indicator)"
        }
    }
    else {

        Write-NoStaticEvidence `
            "No explicit certificate-validation bypass indicator was identified."
    }

    # --------------------------------------------------------
    # TEST 8
    # Private-key exposure
    # --------------------------------------------------------

    Write-Result ""
    Write-Result "[TEST] Private-key exposure"

    $privateKeyPatterns = @(
        "BEGIN PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY"
    )

    $privateKeyEvidence = @(
        $KeyFindings |
        Where-Object {
            $_.Indicator -in $privateKeyPatterns
        }
    )

    if ($privateKeyEvidence.Count -gt 0) {

        Write-Fail `
            "Potential embedded private-key material detected."
    }
    else {

        Write-NoStaticEvidence `
            "No obvious embedded private-key marker was identified."
    }
}

# ============================================================
# DETAILED RUNTIME PROCESS OBSERVATION
# ============================================================

function Start-RuntimeObservation {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process]$Process,

        [Parameter(Mandatory)]
        [int]$ObservationSeconds = 60,

        [Parameter(Mandatory)]
        [int]$IntervalSeconds = 5
    )

    $pidValue = $Process.Id

    Write-Result ""
    Write-Result "============================================================" Cyan
    Write-Result " DETAILED PASSIVE RUNTIME OBSERVATION" Cyan
    Write-Result "============================================================" Cyan

    Write-Result ""
    Write-Result "PID                 : $pidValue"
    Write-Result "Observation period  : $ObservationSeconds seconds"
    Write-Result "Sampling interval   : $IntervalSeconds seconds"
    Write-Result "Observation file    : $script:RuntimeObservationFile"

    Add-Finding `
        -Category "Runtime Observation" `
        -Status "STARTED" `
        -Description "Passive runtime observation started." `
        -Evidence "PID $pidValue; $ObservationSeconds seconds; ${IntervalSeconds}-second sampling."

    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    while ($stopwatch.Elapsed.TotalSeconds -lt $ObservationSeconds) {

        $elapsed =
            [math]::Floor(
                $stopwatch.Elapsed.TotalSeconds
            )

        $processObject = $null

        try {

            $processObject =
                Get-Process `
                    -Id $pidValue `
                    -ErrorAction Stop

            $processObject.Refresh()

            $timestamp = Get-Date

            $cpuSeconds = $null
            $workingSetMB = $null
            $privateMemoryMB = $null
            $virtualMemoryMB = $null
            $threads = $null
            $handles = $null
            $startTime = $null
            $responding = $null
            $hasExited = $processObject.HasExited

            try {
                $cpuSeconds =
                    [math]::Round(
                        $processObject.TotalProcessorTime.TotalSeconds,
                        2
                    )
            }
            catch {}

            try {
                $workingSetMB =
                    [math]::Round(
                        $processObject.WorkingSet64 / 1MB,
                        2
                    )
            }
            catch {}

            try {
                $privateMemoryMB =
                    [math]::Round(
                        $processObject.PrivateMemorySize64 / 1MB,
                        2
                    )
            }
            catch {}

            try {
                $virtualMemoryMB =
                    [math]::Round(
                        $processObject.VirtualMemorySize64 / 1MB,
                        2
                    )
            }
            catch {}

            try {
                $threads =
                    $processObject.Threads.Count
            }
            catch {}

            try {
                $handles =
                    $processObject.HandleCount
            }
            catch {}

            try {
                $startTime =
                    $processObject.StartTime
            }
            catch {}

            try {
                $responding =
                    $processObject.Responding
            }
            catch {}

            Write-Result ""
            Write-Result "------------------------------------------------------------" DarkGray
            Write-Result "Runtime sample: ${elapsed}s" Cyan
            Write-Result "Timestamp       : $($timestamp.ToString('yyyy-MM-dd HH:mm:ss'))"
            Write-Result "PID             : $pidValue"
            Write-Result "Process         : $($processObject.ProcessName)"
            Write-Result "CPU seconds     : $cpuSeconds"
            Write-Result "Working set MB  : $workingSetMB"
            Write-Result "Private memory  : $privateMemoryMB"
            Write-Result "Virtual memory  : $virtualMemoryMB"
            Write-Result "Threads         : $threads"
            Write-Result "Handles         : $handles"
            Write-Result "Responding      : $responding"
            Write-Result "Exited          : $hasExited"

            $tcpConnections = @()

            try {

                if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {

                    $tcpConnections = @(
                        Get-NetTCPConnection `
                            -OwningProcess $pidValue `
                            -ErrorAction SilentlyContinue
                    )
                }
            }
            catch {
                $tcpConnections = @()
            }

            if ($tcpConnections.Count -gt 0) {

                Write-Result ""
                Write-Result "TCP connections associated with PID ${pidValue}:" White

                foreach ($connection in $tcpConnections) {

                    $localAddress =
                        $connection.LocalAddress

                    $localPort =
                        $connection.LocalPort

                    $remoteAddress =
                        $connection.RemoteAddress

                    $remotePort =
                        $connection.RemotePort

                    $state =
                        $connection.State

                    Write-Result `
                        "  $localAddress`:$localPort -> $remoteAddress`:$remotePort [$state]"

                    [void]$script:RuntimeObservations.Add(
                        [PSCustomObject]@{
                            Timestamp       = $timestamp
                            ElapsedSeconds  = $elapsed
                            PID             = $pidValue
                            ProcessName     = $processObject.ProcessName
                            CPUSeconds      = $cpuSeconds
                            WorkingSetMB    = $workingSetMB
                            PrivateMemoryMB = $privateMemoryMB
                            VirtualMemoryMB = $virtualMemoryMB
                            Threads         = $threads
                            Handles         = $handles
                            Responding      = $responding
                            Exited          = $hasExited
                            LocalAddress    = $localAddress
                            LocalPort       = $localPort
                            RemoteAddress   = $remoteAddress
                            RemotePort      = $remotePort
                            State           = $state
                            ObservationType = "TCP"
                        }
                    )
                }
            }
            else {

                Write-Result `
                    "TCP connections associated with PID: none observed."

                [void]$script:RuntimeObservations.Add(
                    [PSCustomObject]@{
                        Timestamp       = $timestamp
                        ElapsedSeconds  = $elapsed
                        PID             = $pidValue
                        ProcessName     = $processObject.ProcessName
                        CPUSeconds      = $cpuSeconds
                        WorkingSetMB    = $workingSetMB
                        PrivateMemoryMB = $privateMemoryMB
                        VirtualMemoryMB = $virtualMemoryMB
                        Threads         = $threads
                        Handles         = $handles
                        Responding      = $responding
                        Exited          = $hasExited
                        LocalAddress    = ""
                        LocalPort       = ""
                        RemoteAddress   = ""
                        RemotePort      = ""
                        State           = ""
                        ObservationType = "PROCESS"
                    }
                )
            }

            if ($hasExited) {

                Write-Review `
                    "Application exited during the observation period."

                break
            }
        }
        catch {

            Write-Review `
                "PID $pidValue could no longer be queried."

            [void]$script:RuntimeObservations.Add(
                [PSCustomObject]@{
                    Timestamp       = Get-Date
                    ElapsedSeconds  = $elapsed
                    PID             = $pidValue
                    ProcessName     = ""
                    CPUSeconds      = ""
                    WorkingSetMB    = ""
                    PrivateMemoryMB = ""
                    VirtualMemoryMB = ""
                    Threads         = ""
                    Handles         = ""
                    Responding      = ""
                    Exited          = $true
                    LocalAddress    = ""
                    LocalPort       = ""
                    RemoteAddress   = ""
                    RemotePort      = ""
                    State           = ""
                    ObservationType = "PROCESS_EXITED"
                }
            )

            break
        }

        $remaining =
            $ObservationSeconds -
            [math]::Floor(
                $stopwatch.Elapsed.TotalSeconds
            )

        if ($remaining -gt $IntervalSeconds) {
            Start-Sleep -Seconds $IntervalSeconds
        }
        elseif ($remaining -gt 0) {
            Start-Sleep -Seconds $remaining
        }
    }

    $stopwatch.Stop()

    Write-Result ""
    Write-Result "============================================================" Cyan
    Write-Result " RUNTIME OBSERVATION COMPLETE" Cyan
    Write-Result "============================================================" Cyan

    Write-Result ""
    Write-Result "PID                 : $pidValue"
    Write-Result "Observed duration   : $([math]::Round($stopwatch.Elapsed.TotalSeconds,2)) seconds"
    Write-Result "Samples recorded    : $($script:RuntimeObservations.Count)"
    Write-Result "Runtime CSV         : $script:RuntimeObservationFile"

    Add-Finding `
        -Category "Runtime Observation" `
        -Status "COMPLETE" `
        -Description "Passive runtime observation completed." `
        -Evidence "PID $pidValue; $([math]::Round($stopwatch.Elapsed.TotalSeconds,2)) seconds; $($script:RuntimeObservations.Count) records."

    # Save immediately.
    try {

        if ($script:RuntimeObservations.Count -gt 0) {

            $script:RuntimeObservations |
                Export-Csv `
                    -LiteralPath $script:RuntimeObservationFile `
                    -NoTypeInformation `
                    -Encoding UTF8 `
                    -Force
        }
    }
    catch {

        Write-Review `
            "Unable to save runtime observation CSV."
    }
}

# ============================================================
# REQUEST EXE
# ============================================================

Write-Result ""
Write-Result "============================================================" Cyan
Write-Result " Certificate Validation & Trust Assessment" Cyan
Write-Result " Generic EXE Assessment" Cyan
Write-Result "============================================================" Cyan
Write-Result ""

do {

    $exePath =
        Read-Host `
            "Enter the full path to the executable"

    if (
        [string]::IsNullOrWhiteSpace(
            $exePath
        )
    ) {

        Write-Result `
            "Please enter an executable path." Yellow

        continue
    }

    $exePath =
        $exePath.Trim().Trim('"')

    if (
        -not (
            Test-Path `
                -LiteralPath $exePath `
                -PathType Leaf
        )
    ) {

        Write-Result `
            "File not found." Red

        continue
    }

    break

} while ($true)

$exePath =
    (Resolve-Path `
        -LiteralPath $exePath).Path

# ============================================================
# VERIFY EXE
# ============================================================

if (
    [System.IO.Path]::GetExtension(
        $exePath
    ).ToLowerInvariant() -ne ".exe"
) {

    Write-Fail `
        "The selected file is not an .exe."

    exit
}

# ============================================================
# CREATE LOCAL RESULT DIRECTORY
#
# Results are stored beside the PowerShell script:
#
# Results\
#   ExecutableName\
#       yyyyMMdd\
#
# ============================================================

$resultsRoot =
    Join-Path `
        -Path $PSScriptRoot `
        -ChildPath "Results"

$exeName =
    [System.IO.Path]::GetFileNameWithoutExtension(
        $exePath
    )

$safeExeName =
    $exeName -replace '[<>:"/\\|?*]', '_'

$dateFolder =
    Get-Date -Format "yyyyMMdd"

$timeStamp =
    Get-Date -Format "yyyyMMdd_HHmmss"

$resultDirectory =
    Join-Path `
        -Path $resultsRoot `
        -ChildPath $safeExeName

$resultDirectory =
    Join-Path `
        -Path $resultDirectory `
        -ChildPath $dateFolder

New-Item `
    -ItemType Directory `
    -Path $resultDirectory `
    -Force `
    -ErrorAction Stop |
    Out-Null

# ============================================================
# OUTPUT FILES
# ============================================================

$script:OutputFile =
    Join-Path `
        -Path $resultDirectory `
        -ChildPath "${safeExeName}_Certificate_Trust_Assessment_${timeStamp}.txt"

$script:RuntimeObservationFile =
    Join-Path `
        -Path $resultDirectory `
        -ChildPath "${safeExeName}_Runtime_Observation_${timeStamp}.csv"

$script:FindingsFile =
    Join-Path `
        -Path $resultDirectory `
        -ChildPath "${safeExeName}_Findings_${timeStamp}.csv"

New-Item `
    -ItemType File `
    -Path $script:OutputFile `
    -Force `
    -ErrorAction Stop |
    Out-Null

# ============================================================
# ASSESSMENT HEADER
# ============================================================

Write-Result ""
Write-Result "============================================================" Cyan
Write-Result " Certificate Validation & Trust Assessment" Cyan
Write-Result "============================================================" Cyan
Write-Result ""

Write-Result `
    "Assessment started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

Write-Result `
    "Computer           : $env:COMPUTERNAME"

Write-Result `
    "User               : $env:USERNAME"

Write-Result `
    "PowerShell         : $($PSVersionTable.PSVersion)"

Write-Result `
    "Executable         : $exePath"

Write-Result `
    "Output directory   : $resultDirectory"

Write-Result `
    "Assessment TXT     : $script:OutputFile"

Write-Result `
    "Runtime CSV        : $script:RuntimeObservationFile"

Write-Result `
    "Findings CSV       : $script:FindingsFile"

Write-Result ""

Write-Result "Scanning:" Cyan
Write-Result $exePath
Write-Result ""

# ============================================================
# AUTHENTICODE
# ============================================================

Write-Result "============================================================"
Write-Result " AUTHENTICODE"
Write-Result "============================================================"

try {

    $signature =
        Get-AuthenticodeSignature `
            -FilePath $exePath

    Write-Result ""

    Write-Result `
        "Status        : $($signature.Status)"

    Write-Result `
        "Status Message: $($signature.StatusMessage)"

    if ($signature.Status -eq "Valid") {

        Write-Pass `
            "Authenticode signature is valid."
    }
    else {

        Write-Fail `
            "Authenticode status: $($signature.Status)"
    }

    if ($signature.SignerCertificate) {

        Write-Result ""
        Write-Result "Signing Certificate" White

        Write-Result `
            "Subject        : $($signature.SignerCertificate.Subject)"

        Write-Result `
            "Issuer         : $($signature.SignerCertificate.Issuer)"

        Write-Result `
            "Thumbprint     : $($signature.SignerCertificate.Thumbprint)"

        Write-Result `
            "Serial Number  : $($signature.SignerCertificate.SerialNumber)"

        Write-Result `
            "Valid From     : $($signature.SignerCertificate.NotBefore)"

        Write-Result `
            "Valid Until    : $($signature.SignerCertificate.NotAfter)"

        Write-Result `
            "Signature Algo : $($signature.SignerCertificate.SignatureAlgorithm.FriendlyName)"
    }
}
catch {

    $reason = $_.Exception.Message

    if ([string]::IsNullOrWhiteSpace($reason)) {
        $reason = "Unknown Authenticode error."
    }

    Write-Fail `
        "Unable to retrieve Authenticode signature."

    Write-Result $reason
}

# ============================================================
# WINDOWS CERTIFICATE STORES
# ============================================================

Write-Result ""
Write-Result "============================================================"
Write-Result " WINDOWS CERTIFICATE STORES"
Write-Result "============================================================"

$stores = @(
    "Cert:\CurrentUser\Root",
    "Cert:\CurrentUser\CA",
    "Cert:\LocalMachine\Root",
    "Cert:\LocalMachine\CA"
)

$storeEnumerationSuccessful = $true

foreach ($storePath in $stores) {

    Write-Result ""
    Write-Result $storePath Cyan

    try {

        $certificates = @(
            Get-ChildItem `
                -Path $storePath `
                -ErrorAction Stop
        )

        Write-Result `
            "Certificates found: $($certificates.Count)"
    }
    catch {

        $storeEnumerationSuccessful = $false

        Write-Review `
            "Unable to access certificate store."
    }
}

if ($storeEnumerationSuccessful) {

    Write-Pass `
        "Windows certificate stores were successfully enumerated."
}
else {

    Write-Review `
        "One or more Windows certificate stores could not be enumerated."
}

Write-NotEstablished `
    "Enumeration of Windows stores does not prove that the application itself uses every store."

Write-NotEstablished `
    "Application-specific certificate stores have not been identified or independently verified."

# ============================================================
# APPLICATION FILES
# ============================================================

Write-Result ""
Write-Result "============================================================"
Write-Result " APPLICATION FILES"
Write-Result "============================================================"

$applicationFiles =
    @(
        Get-ApplicationFiles `
            -ExecutablePath $exePath
    )

foreach ($applicationFile in $applicationFiles) {

    Write-Result $applicationFile
}

# ============================================================
# HTTPS ENDPOINT DISCOVERY
# ============================================================

Write-Result ""
Write-Result "============================================================"
Write-Result " HTTPS ENDPOINT DISCOVERY"
Write-Result "============================================================"

$discoveredEndpoints =
    @(
        Get-HttpsEndpoints `
            -Files $applicationFiles
    )

if ($discoveredEndpoints.Count -eq 0) {

    Write-Review `
        "No HTTPS URLs were discovered."

    Write-Result ""

    Write-Result `
        "This does NOT prove that the application does not use HTTPS."

    Write-Result `
        "Endpoints may be constructed dynamically or stored elsewhere."
}
else {

    Write-Result ""
    Write-Result `
        "Discovered HTTPS endpoints:" White

    foreach ($discoveredEndpoint in $discoveredEndpoints) {

        Write-Result `
            "  https://$discoveredEndpoint"
    }
}

# ============================================================
# LIVE TLS TESTING
# ============================================================

foreach ($discoveredEndpoint in $discoveredEndpoints) {

    Test-TlsEndpoint `
        -Endpoint $discoveredEndpoint
}

# ============================================================
# STATIC CONFIGURATION ANALYSIS
# ============================================================

Write-Result ""
Write-Result "============================================================"
Write-Result " STATIC TLS / CERTIFICATE ANALYSIS"
Write-Result "============================================================"

$configFindings =
    @(
        Find-TlsIndicators `
            -Files $applicationFiles
    )

if ($configFindings.Count -gt 0) {

    Write-Review `
        "Potential TLS/certificate-related indicators found in configuration/text files."

    foreach ($finding in $configFindings) {

        Write-Result ""

        Write-Result `
            "File      : $($finding.File)"

        Write-Result `
            "Line      : $($finding.Line)"

        Write-Result `
            "Indicator : $($finding.Indicator)"

        Write-Result `
            "Text      : $($finding.Text)"

        Add-Finding `
            -Category "Configuration TLS Indicator" `
            -Status "REVIEW" `
            -Description $finding.Indicator `
            -Evidence "$($finding.File):$($finding.Line) - $($finding.Text)"
    }
}
else {

    Write-NoStaticEvidence `
        "No meaningful TLS/certificate indicators found in configuration files."
}

# ============================================================
# EXECUTABLE STATIC ANALYSIS
# ============================================================

Write-Result ""
Write-Result "============================================================"
Write-Result " EXECUTABLE TLS / CERTIFICATE ANALYSIS"
Write-Result "============================================================"

$exeFindings =
    @(
        Find-ExecutableIndicators `
            -ExecutablePath $exePath
    )

if ($exeFindings.Count -gt 0) {

    Write-Review `
        "Potential TLS/certificate-related strings found in the executable."

    foreach ($finding in $exeFindings) {

        Write-Result ""

        Write-Result `
            "Indicator : $($finding.Indicator)"

        Write-Result `
            "String    : $($finding.String)"

        Add-Finding `
            -Category "Executable TLS Indicator" `
            -Status "REVIEW" `
            -Description $finding.Indicator `
            -Evidence $finding.String
    }

    Write-Result ""

    Write-Result `
        "These are static indicators only and do not prove runtime behaviour." Yellow
}
else {

    Write-NoStaticEvidence `
        "No obvious TLS/certificate validation indicators found."
}

# ============================================================
# CERTIFICATE / PRIVATE KEY SEARCH
# ============================================================

Write-Result ""
Write-Result "============================================================"
Write-Result " CERTIFICATE / PRIVATE KEY INDICATORS"
Write-Result "============================================================"

$keyFindings =
    @(
        Find-CertificateKeyIndicators `
            -Files $applicationFiles
    )

if ($keyFindings.Count -gt 0) {

    Write-Review `
        "Certificate/key-related indicators found."

    foreach ($finding in $keyFindings) {

        Write-Result ""

        Write-Result `
            "File      : $($finding.File)"

        Write-Result `
            "Indicator : $($finding.Indicator)"

        Add-Finding `
            -Category "Certificate/Key Indicator" `
            -Status "REVIEW" `
            -Description $finding.Indicator `
            -Evidence $finding.File
    }
}
else {

    Write-NoStaticEvidence `
        "No obvious certificate/private-key markers found."
}

# ============================================================
# SAFE RUNTIME TLS ASSESSMENT
# ============================================================

Write-Result ""
Write-Result "============================================================"
Write-Result " SAFE RUNTIME TLS ASSESSMENT"
Write-Result "============================================================"

if ($discoveredEndpoints.Count -eq 0) {

    Write-NotEstablished `
        "No discovered HTTPS endpoints are available for runtime TLS assessment."
}
else {

    foreach ($runtimeEndpoint in $discoveredEndpoints) {

        Test-RuntimeTlsPolicy `
            -Endpoint $runtimeEndpoint `
            -ExecutablePath $exePath `
            -ExecutableFindings @($exeFindings) `
            -KeyFindings @($keyFindings)
    }
}

# ============================================================
# OPTIONAL APPLICATION LAUNCH
# ============================================================

Write-Result ""
Write-Result "============================================================"
Write-Result " OPTIONAL APPLICATION RUNTIME OBSERVATION"
Write-Result "============================================================"

$launchChoice =
    Read-Host `
        "Launch the EXE for passive observation? (Y/N)"

if ($launchChoice -match '^(Y|YES)$') {

    $observedProcess = $null

    try {

        $applicationDirectory =
            Split-Path `
                -Parent `
                $exePath

        if (
            [string]::IsNullOrWhiteSpace(
                $applicationDirectory
            )
        ) {

            throw `
                "Unable to determine the application's directory."
        }

        Write-Result ""
        Write-Result "Application directory:" Cyan
        Write-Result $applicationDirectory
        Write-Result ""

        $modulesDirectory =
            Join-Path `
                -Path $applicationDirectory `
                -ChildPath "Modules"

        if (
            Test-Path `
                -LiteralPath $modulesDirectory `
                -PathType Container
        ) {

            Write-Pass `
                "Application Modules directory found."

            Write-Result `
                "  $modulesDirectory"
        }
        else {

            Write-Review `
                "Application Modules directory was not found."

            Write-Result `
                "  Expected: $modulesDirectory"
        }

        Write-Result ""
        Write-Result `
            "Launching application from its own directory..." Cyan

        $observedProcess =
            Start-Process `
                -FilePath $exePath `
                -WorkingDirectory $applicationDirectory `
                -PassThru

        Write-Pass `
            "Application started. PID: $($observedProcess.Id)"

        Write-Result ""
        Write-Result `
            "Executable : $exePath"

        Write-Result `
            "Working Dir: $applicationDirectory"

        Write-Result `
            "PID        : $($observedProcess.Id)"

        Write-Result ""

        Write-Result `
            "The application has been launched without modifying:" White

        Write-Result `
            "  - certificate stores"

        Write-Result `
            "  - proxy settings"

        Write-Result `
            "  - hosts file"

        Write-Result `
            "  - executable"

        Write-Result `
            "  - application configuration"

        # ----------------------------------------------------
        # 60 SECOND DETAILED OBSERVATION
        # ----------------------------------------------------

        Start-RuntimeObservation `
            -Process $observedProcess `
            -ObservationSeconds 60 `
            -IntervalSeconds 5

        # ----------------------------------------------------
        # FINAL PROCESS STATE
        # ----------------------------------------------------

        try {

            $finalProcess =
                Get-Process `
                    -Id $observedProcess.Id `
                    -ErrorAction Stop

            $finalProcess.Refresh()

            Write-Result ""
            Write-Result "Final process state:" White

            Write-Result `
                "PID             : $($finalProcess.Id)"

            Write-Result `
                "Process Name    : $($finalProcess.ProcessName)"

            Write-Result `
                "Working Set MB  : $([math]::Round($finalProcess.WorkingSet64 / 1MB,2))"

            Write-Result `
                "Threads         : $($finalProcess.Threads.Count)"

            Write-Result `
                "Handles         : $($finalProcess.HandleCount)"

            if ($finalProcess.HasExited) {

                Write-Review `
                    "Application exited following the observation period."
            }
            else {

                Write-Pass `
                    "Application remained running following the observation period."
            }
        }
        catch {

            Write-Review `
                "Unable to retrieve final process state."
        }
    }
    catch {

        $reason = $_.Exception.Message

        if ([string]::IsNullOrWhiteSpace($reason)) {
            $reason = "Unknown application launch error."
        }

        Write-Fail `
            "Unable to launch or observe application."

        Write-Result `
            "Reason: $reason"
    }
}
else {

    Write-Result `
        "Application launch skipped."
}

# ============================================================
# TEST LIMITATIONS
# ============================================================

Write-Result ""
Write-Result "============================================================" Cyan
Write-Result " RUNTIME TEST LIMITATIONS" Cyan
Write-Result "============================================================"

Write-Result ""

Write-Manual `
    "Expired-certificate rejection by the EXE requires a controlled expired-certificate endpoint."

Write-Manual `
    "Self-signed-certificate rejection by the EXE requires a controlled self-signed endpoint."

Write-Manual `
    "Unexpected-CA rejection by the EXE requires a controlled test CA."

Write-Manual `
    "User-installed CA behaviour requires a controlled authorised test CA."

Write-Manual `
    "Broken/incomplete chain rejection requires a controlled certificate-chain test."

Write-Manual `
    "Certificate revocation behaviour requires controlled authorised testing."

Write-Manual `
    "Certificate pinning requires an alternative certificate to be presented to the application."

Write-Manual `
    "Public-key pinning requires an alternative public key to be presented to the application."

Write-Manual `
    "Custom validation callbacks require observation of the application's actual TLS connection."

Write-Manual `
    "Sensitive-operation continuation after TLS failure requires application-specific functional testing."

# ============================================================
# FINAL ASSESSMENT
# ============================================================

Write-Result ""
Write-Result "============================================================"
Write-Result " ASSESSMENT SUMMARY"
Write-Result "============================================================"

Write-Result ""

Write-Result "STATUS DEFINITIONS" White

Write-Result ""
Write-Result "[PASS] PASS = Directly demonstrated by the current automated test."
Write-Result "[REVIEW] REVIEW = Evidence exists, but application-level behaviour is not proven."
Write-Result "[NO STATIC EVIDENCE] = Nothing obvious was found; this is not proof of absence."
Write-Result "[NOT ESTABLISHED] = Controlled application-level testing is required."

Write-Result ""
Write-Result "AUTOMATED / PARTIALLY AUTOMATED:" White

Write-Result ""
Write-Result "  [CHECK] Authenticode signature"
Write-Result "  [CHECK] Signing certificate details"
Write-Result "  [CHECK] Certificate validity dates"
Write-Result "  [CHECK] Windows certificate stores"
Write-Result "  [CHECK] HTTPS endpoint discovery"
Write-Result "  [CHECK] Remote certificate details"
Write-Result "  [CHECK] Remote certificate expiry"
Write-Result "  [CHECK] Windows certificate-chain build"
Write-Result "  [CHECK] Hostname validation from scanner process"
Write-Result "  [CHECK] Static TLS/certificate indicators"
Write-Result "  [CHECK] Certificate/private-key indicators"
Write-Result "  [CHECK] Static pinning indicators"
Write-Result "  [CHECK] Static validation-callback indicators"
Write-Result "  [CHECK] Static validation-bypass indicators"
Write-Result "  [CHECK] 60-second passive runtime observation"
Write-Result "  [CHECK] Runtime PID/process monitoring"
Write-Result "  [CHECK] Runtime TCP connection monitoring"

Write-Result ""
Write-Result "RUNTIME VALIDATION STILL REQUIRED:" White

Write-Result ""

Write-Manual `
    "EXE hostname validation"

Write-Manual `
    "EXE rejection of an expired server certificate"

Write-Manual `
    "EXE rejection of a self-signed server certificate"

Write-Manual `
    "EXE rejection of a certificate signed by an unexpected CA"

Write-Manual `
    "EXE behaviour when a user-installed CA is trusted"

Write-Manual `
    "EXE rejection of a broken/incomplete certificate chain"

Write-Manual `
    "EXE behaviour when certificate revocation checking fails"

Write-Manual `
    "Application-specific certificate-store usage"

Write-Manual `
    "Certificate pinning enforcement"

Write-Manual `
    "Public-key pinning enforcement"

Write-Manual `
    "Custom certificate-validation callback behaviour"

Write-Manual `
    "Certificate-validation bypass behaviour"

Write-Manual `
    "Application behaviour after TLS validation failure"

Write-Manual `
    "Whether sensitive operations continue after TLS validation failure"

# ============================================================
# SAVE STRUCTURED FINDINGS
# ============================================================

try {

    if ($script:Findings.Count -gt 0) {

        $script:Findings |
            Export-Csv `
                -LiteralPath $script:FindingsFile `
                -NoTypeInformation `
                -Encoding UTF8 `
                -Force
    }
    else {

        $emptyFinding =
            [PSCustomObject]@{
                Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Category    = "Assessment"
                Status      = "NO DATA"
                Description = "No structured findings were recorded."
                Evidence    = ""
            }

        @($emptyFinding) |
            Export-Csv `
                -LiteralPath $script:FindingsFile `
                -NoTypeInformation `
                -Encoding UTF8 `
                -Force
    }
}
catch {

    Write-Review `
        "Unable to save structured findings CSV."
}

# ============================================================
# FINISH
# ============================================================

$assessmentFinished = Get-Date

Write-Result ""
Write-Result "============================================================" Cyan
Write-Result " COMPLETE" Cyan
Write-Result "============================================================" Cyan

Write-Result ""

Write-Result `
    "Assessment finished : $($assessmentFinished.ToString('yyyy-MM-dd HH:mm:ss'))"

$duration =
    $assessmentFinished -
    $script:AssessmentStarted

Write-Result `
    "Assessment duration : $($duration.ToString())"

Write-Result ""

Write-Result `
    "Results saved to:" White

Write-Result `
    $resultDirectory Cyan

Write-Result ""

Write-Result `
    "Assessment TXT:" White

Write-Result `
    $script:OutputFile Cyan

Write-Result ""

Write-Result `
    "Runtime observation CSV:" White

Write-Result `
    $script:RuntimeObservationFile Cyan

Write-Result ""

Write-Result `
    "Structured findings CSV:" White

Write-Result `
    $script:FindingsFile Cyan

Write-Result ""

# Final attempt to save findings after all summary entries.
try {

    if ($script:Findings.Count -gt 0) {

        $script:Findings |
            Export-Csv `
                -LiteralPath $script:FindingsFile `
                -NoTypeInformation `
                -Encoding UTF8 `
                -Force
    }
}
catch {
    # Do not prevent completion.
}

Read-Host "Press ENTER to exit"
