# ==================================================================================== #
#                      Copyright (c) 2024-2025 Mehrad Pooryoussof                      #
#                        github.com/MPCodeWriter21/UT-Internet                         #
# ==================================================================================== #
# - What is this script?                                                               #
# + This script is a PowerShell script that logs you into the UT network.              #
#                                                                                      #
# - What are its features?                                                             #
# + It can save your credentials for future use.                                       #
# + You can reset your saved credentials.                                              #
# + You can choose not to save your credentials.                                       #
# + You can add multiple accounts.                                                     #
# + You can choose the default account or another account to log in with.              #
# + It can detect if you are already logged in.                                        #
# + It can log you out if you are already logged in.                                   #
# + It can show your remaining traffic.                                                #
#                                                                                      #
# - How to use it?                                                                     #
# + Run the script using PowerShell.                                                   #
# + Enter your username and password.                                                  #
# + If you want to save your credentials, don't use the '-noSave' flag.                #
# + If you want to reset your saved credentials, use the '-reset' flag.                #
# + If you don't want to see your remaining traffic, use '-noRemainingTraffic'.        #
# ==================================================================================== #

param (
    [switch]$reset = $false,
    [switch]$noSave = $false,
    [switch]$addAccount = $false,
    [switch]$chooseDefault = $false,
    [switch]$chooseAccount = $false,
    [switch]$noRemainingTraffic = $false,
    [switch]$noUpdateCheck = $false,
    [switch]$help = $false,
    [switch]$version = $false
)

[string]$currentVersion = "1.4.0"

Write-Host -ForegroundColor Yellow "================================================================================"
Write-Host -ForegroundColor White  "           Copyright (C) 2024-2025 CodeWriter21 - Mehrad Pooryoussof            "
Write-Host -ForegroundColor White  "                     github.com/MPCodeWriter21/UT-Internet                      "
Write-Host -ForegroundColor Yellow "================================================================================"
Write-Host -ForegroundColor White

function Show-Info {
    Write-Host -NoNewLine -ForegroundColor Cyan " ["
    Write-Host -NoNewLine -ForegroundColor Blue "i"
    Write-Host -NoNewLine -ForegroundColor Cyan "] "
    Write-Host -ForegroundColor White "$args"
}

function Show-Error {
    Write-Host -NoNewLine -ForegroundColor Cyan " ["
    Write-Host -NoNewLine -ForegroundColor Red "-"
    Write-Host -NoNewLine -ForegroundColor Cyan "] "
    Write-Host -ForegroundColor White "$args"
}

function Show-Success {
    Write-Host -NoNewLine -ForegroundColor Cyan " ["
    Write-Host -NoNewLine -ForegroundColor Green "+"
    Write-Host -NoNewLine -ForegroundColor Cyan "] "
    Write-Host -ForegroundColor White "$args"
}

function Get-CredentialObject {
    param (
        [string]$credentialFilePath
    )

    [string]$credentialData = Get-Content -ErrorAction SilentlyContinue $credentialFilePath

    if (-not $credentialData) {
        return $null
    }

    try {
        $credentialObject = ConvertFrom-Json $credentialData

        # Check if the $credentialData is an array of two elements
        # Migrate old format to new format
        # Old format: ["username", "securePassword"]
        # New format: { "default": ["username", "securePassword"] or null, "accounts": [ ["username", "securePassword"], ["username2", "securePassword2"] ] }
        if ($credentialObject -is [array] -and $credentialObject.Count -eq 2) {
            Show-Info "Detected old credential format. Migrating to new format..."
            $credentialObject = @{
                default  = $null
                accounts = @(, @($credentialObject[0], $credentialObject[1]))
            }
            $credentialData = ConvertTo-Json $credentialObject
            $credentialData | Set-Content -Path $credentialFilePath
        }

        return $credentialObject
    }
    catch {
        Show-Error "Failed to parse credential data."
        return $null
    }
}

function Save-CredentialObject {
    param (
        [Parameter(Mandatory = $true)]
        $credentialObject,

        [Parameter(Mandatory = $true)]
        [string]$filePath
    )

    try {
        $credentialData = $credentialObject | ConvertTo-Json
        $credentialData | Set-Content -Path $filePath

        $credentialFile = Get-ChildItem -Force $filePath
        $credentialFile.Attributes = $credentialFile.Attributes -bor [System.IO.FileAttributes]::Hidden
        $credentialFile.Attributes = $credentialFile.Attributes -bor [System.IO.FileAttributes]::System
        $credentialFile.Attributes = $credentialFile.Attributes -band (-bnot [System.IO.FileAttributes]::Archive)

        return $true
    }
    catch {
        Show-Error "Failed to save credentials: $_"
        return $false
    }
}

function Show-AccountList {
    param (
        [Parameter(Mandatory = $true)]
        $credentialObject,

        [bool]$showDefaultIndicator = $true
    )

    Show-Info "Saved accounts:"
    $index = 1
    if ($showDefaultIndicator -and $credentialObject.default) {
        foreach ($account in $credentialObject.accounts) {
            $username = $account[0]
            $isDefault = ($username -eq $credentialObject.default[0])
            if ($isDefault) {
                Write-Host -NoNewLine -ForegroundColor Cyan " [$index] "
                Write-Host -NoNewLine -ForegroundColor Green "$username"
                Write-Host -ForegroundColor Yellow " (default)"
            }
            else {
                Write-Host -ForegroundColor Cyan " [$index] $username"
            }
            $index++
        }
    }
    else {
        foreach ($account in $credentialObject.accounts) {
            $username = $account[0]
            Write-Host -ForegroundColor Cyan " [$index] $username"
            $index++
        }
    }
}

function Get-AccountSelection {
    param (
        [Parameter(Mandatory = $true)]
        $credentialObject,

        [Parameter(Mandatory = $true)]
        [string]$prompt
    )

    $choice = Read-Host -Prompt $prompt

    try {
        $choiceNum = [int]$choice
        if ($choiceNum -lt 1 -or $choiceNum -gt $credentialObject.accounts.Count) {
            Show-Error "Invalid choice. Please enter a number between 1 and $($credentialObject.accounts.Count)."
            return $null
        }

        return $credentialObject.accounts[$choiceNum - 1]
    }
    catch {
        Show-Error "Invalid input. Please enter a valid number."
        return $null
    }
}

function Add-NewAccount {
    param (
        [Parameter(Mandatory = $true)]
        $credentialObject,

        [Parameter(Mandatory = $true)]
        [string]$filePath
    )

    Write-Host
    Show-Info "Adding a new account..."
    $newUsername = Read-Host -Prompt " [?] Please enter the new username"
    $newPassword = Read-Host -Prompt " [?] Please enter the new password" -AsSecureString
    $newPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPassword))
    $newSecurePassword = $newPasswordPlain | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString

    # Check if account already exists
    $accountExists = $false
    foreach ($account in $credentialObject.accounts) {
        if ($account[0] -eq $newUsername) {
            $accountExists = $true
            Show-Error "Account '$newUsername' already exists!"
            $title = " [!] Update existing account?"
            $question = " [?] Do you want to update the password for this account?"
            $choices = "&Yes", "&No"

            $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
            if ($decision -eq 0) {
                $account[1] = $newSecurePassword
                Show-Success "Password updated for account '$newUsername'."
            }
            else {
                return $false
            }
            break
        }
    }

    if (-not $accountExists) {
        $credentialObject.accounts += , @($newUsername, $newSecurePassword)
        Show-Success "Account '$newUsername' added successfully!"
    }

    # Save updated credentials
    if (Save-CredentialObject -credentialObject $credentialObject -filePath $filePath) {
        Show-Success "Credentials saved."
        return $true
    }
    else {
        return $false
    }
}

if ($help) {
    Show-Info "This script logs you into the UT network."
    Write-Host
    Show-Info "Usage: SCRIPT_NAME [-reset] [-noSave] [-noRemainingTraffic] [-noUpdateCheck] [-help]"
    Show-Info "Options:"
    Show-Info "  -reset              Reset saved credentials."
    Show-Info "  -noSave             Do not save credentials."
    Show-Info "  -addAccount         Add another account."
    Show-Info "  -chooseDefault      Set or unset default account"
    Show-Info "  -chooseAccount      Choose an account from the added accounts. (Keeps the default unchanged)"
    Show-Info "  -noRemainingTraffic Do not show remaining traffic."
    Show-Info "  -noUpdateCheck      Do not check for updates on GitHub."
    Show-Info "  -help               Show this help message."
    Show-Info "  -version            Show the version of the script."
    exit 0
}

if ($version) {
    Show-Info "Version: $currentVersion"
    exit 0
}

$savedCredentials = $false
$credentialFilePath = "$HOME\.ut.net.creds"

if ($reset) {
    Remove-Item -Path $credentialFilePath -Force -ErrorAction SilentlyContinue
    Show-Success "Saved credentials have been reset."
}

$credentialObject = Get-CredentialObject -credentialFilePath $credentialFilePath

# Handle -addAccount flag
if ($addAccount) {
    if (-not $credentialObject) {
        Show-Info "No saved credentials found. The -addAccount flag will be ignored."
        Show-Info "Please complete the initial login first, then use -addAccount to add more accounts."
        Write-Host
        # Don't exit - let the user continue with normal login
    }
    else {
        if (Add-NewAccount -credentialObject $credentialObject -filePath $credentialFilePath) {
            pause
            exit 0
        }
        else {
            pause
            exit 1
        }
    }
}

# Handle -chooseDefault flag
if ($chooseDefault) {
    if (-not $credentialObject) {
        Show-Error "No saved credentials found. Please run the script without flags first to save credentials."
        pause
        exit 1
    }

    if ($credentialObject.accounts.Count -eq 1) {
        Show-Info "Only one account saved. No need to choose."
        pause
        exit 0
    }

    Show-AccountList -credentialObject $credentialObject -showDefaultIndicator $true
    Write-Host -ForegroundColor Cyan " [0] None (prompt for account selection on each login)"

    Write-Host
    $choice = Read-Host -Prompt " [?] Enter the number of the account to set as default (or 0 for none)"

    try {
        $choiceNum = [int]$choice

        if ($choiceNum -eq 0) {
            # Set default to null - user will be prompted each time
            $credentialObject.default = $null

            if (Save-CredentialObject -credentialObject $credentialObject -filePath $credentialFilePath) {
                Show-Success "Default account cleared. You will be prompted to choose an account on each login."
                pause
                exit 0
            }
            else {
                pause
                exit 1
            }
        }
        elseif ($choiceNum -lt 1 -or $choiceNum -gt $credentialObject.accounts.Count) {
            Show-Error "Invalid choice. Please enter a number between 0 and $($credentialObject.accounts.Count)."
            pause
            exit 1
        }
        else {
            $selectedAccount = $credentialObject.accounts[$choiceNum - 1]
            $credentialObject.default = $selectedAccount

            if (Save-CredentialObject -credentialObject $credentialObject -filePath $credentialFilePath) {
                Show-Success "Default account set to: $($selectedAccount[0])"
                pause
                exit 0
            }
            else {
                pause
                exit 1
            }
        }
    }
    catch {
        Show-Error "Invalid input. Please enter a valid number."
        pause
        exit 1
    }
}

# Handle -chooseAccount flag
if ($chooseAccount) {
    if (-not $credentialObject) {
        Show-Error "No saved credentials found. Please run the script without flags first to save credentials."
        pause
        exit 1
    }

    if ($credentialObject.accounts.Count -eq 1) {
        Show-Info "Only one account saved. Using it for login."
        $selectedAccount = $credentialObject.accounts[0]
    }
    else {
        Show-AccountList -credentialObject $credentialObject -showDefaultIndicator $true

        Write-Host
        $selectedAccount = Get-AccountSelection -credentialObject $credentialObject -prompt " [?] Enter the number of the account to use for login"

        if (-not $selectedAccount) {
            pause
            exit 1
        }
    }

    # Use selected account for this session
    [string]$UT_USERNAME = $selectedAccount[0]
    [SecureString]$SECURE_UT_PASSWORD = $selectedAccount[1] | ConvertTo-SecureString -ErrorAction Stop
    $UT_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SECURE_UT_PASSWORD))
    $savedCredentials = $true

    Show-Success "Using account: $UT_USERNAME"
    # Continue with login process - don't exit
}

function Get-Ip ([string[]]$dnsServers, [string]$domain) {
    $ip = $null
    # Resolve the IP using the DNS servers
    $ip = foreach ($dns in $dnsServers) {
        try {
            $resolved = Resolve-DnsName -Name $domain -Server $dns -Type A -ErrorAction Stop
            if ($resolved) {
                $resolved.IPAddress[0]
                break
            }
        }
        catch {
            continue
        }
    }

    if (-not $ip) {
        # Try finding IP with the default DNS
        try {
            $resolved = Resolve-DnsName -Name $domain -Type A -ErrorAction Stop
            if ($resolved) {
                $ip = $resolved.IPAddress[0]
            }
        }
        catch {}
    }

    return $ip
}

$internetDomain = "internet.ut.ac.ir"
$acctDomain = "acct.ut.ac.ir"
$dnsServers = @("192.168.20.14", "192.168.20.15")

Show-Info "Finding the Login server..."
# Resolve IP of 'internet.ut.ac.ir' by querying specified DNS servers
$ip = Get-Ip -dnsServers $dnsServers -domain $internetDomain
$acctIp = $null

if (-not $ip) {
    Show-Error "Failed to find IP for the login server."
    Show-Info "Make sure you are connected to the UT network."
    Show-Info "Check if any VPN, Proxy, or Firewall is blocking the connection."
    pause
    exit 1
}
Show-Success "IP: '$ip'"

function Get-Magic {
    Write-Host
    Show-Info "Getting the magic..."

    # Make a request to retrieve the magic token
    $portalUrl = "https://$ip`:1003/portal?0"
    $magicResponse = Invoke-WebRequest -Uri $portalUrl -Headers @{
        Host = "$internetDomain`:1003"
    } -UseBasicParsing

    # Extract the magic token from the response HTML
    if ($magicResponse.Content -match '<input type="hidden" name="magic" value="(.*)">') {
        $magic = $matches[1]
    }
    else {
        $magic = ""
    }

    if (-not $magic) {
        # Check if the user is already logged in
        if ($magicResponse.Content -match '<a href="https://internet.ut.ac.ir:1003/logout\?">') {
            Show-Success "You seem to be logged in already..."
            $title = " [!] Wanna logout?"
            $question = " [?] Do you want to log out?"
            $choices = "&Yes", "&No"

            $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
            if ($decision -eq 0) {
                Show-Info "Logging out..."
                $logoutUrl = "https://$ip`:1003/logout?0"
                $logoutResponse = Invoke-WebRequest -Uri $logoutUrl -Headers @{
                    Host = "$internetDomain`:1003"
                } -UseBasicParsing
                if ($logoutResponse.Content -match '<script language="JavaScript">window.location="https://internet.ut.ac.ir:1003/login') {
                    Show-Success "Successfully logged out."
                }
                else {
                    Show-Error "Failed to log out!"
                }
            }
            else {
                Show-Error "You did not log out."
            }
        }
        else {
            Show-Error "Failed to retrieve magic token."
        }
        pause
        exit 1
    }

    Show-Success "Magic: $magic"
    return $magic
}

$magicValue = Get-Magic

if ($credentialObject) {
    try {
        Show-Success "Found saved credentials."
        Show-Info "Use '-reset' flag to enter new credentials."
        Show-Info "Use '-addAccount' flag to add another account."

        # If chooseAccount flag is not set, use default account
        if (-not $chooseAccount) {
            # If default is null and multiple accounts exist, prompt user
            if ($null -eq $credentialObject.default -and $credentialObject.accounts.Count -gt 1) {
                Write-Host
                Show-Info "No default account set. Please choose an account:"
                Show-Info "Tip: Use '-chooseDefault' flag to set a default account and skip this prompt."
                Write-Host
                Show-AccountList -credentialObject $credentialObject -showDefaultIndicator $false
                Write-Host
                $selectedAccount = Get-AccountSelection -credentialObject $credentialObject -prompt " [?] Enter the number of the account to use"

                if ($selectedAccount) {
                    [string]$UT_USERNAME = $selectedAccount[0]
                    [SecureString]$SECURE_UT_PASSWORD = $selectedAccount[1] | ConvertTo-SecureString -ErrorAction Stop
                    $UT_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SECURE_UT_PASSWORD))
                    $savedCredentials = $true
                }
            }
            # If only one account exists, use it automatically
            elseif ($credentialObject.accounts.Count -eq 1) {
                [string]$UT_USERNAME = $credentialObject.accounts[0][0]
                [SecureString]$SECURE_UT_PASSWORD = $credentialObject.accounts[0][1] | ConvertTo-SecureString -ErrorAction Stop
                $UT_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SECURE_UT_PASSWORD))
                $savedCredentials = $true
            }
            # Use default account
            elseif ($credentialObject.default) {
                Write-Host
                Show-Info "Using default account: $($credentialObject.default[0])"
                Show-Info "Use '-chooseDefault' flag to change the default account."
                [string]$UT_USERNAME = $credentialObject.default[0]
                [SecureString]$SECURE_UT_PASSWORD = $credentialObject.default[1] | ConvertTo-SecureString -ErrorAction Stop
                $UT_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SECURE_UT_PASSWORD))
                $savedCredentials = $true
            }
        }
    }
    catch {
        Show-Error "Failed to use the saved credentials. $_"
    }
}

if (-not $savedCredentials) {
    # Prompt for username
    $UT_USERNAME = Read-Host -Prompt "`n [?] Please enter your username"

    # Prompt for password (masked input)
    $UT_PASSWORD = Read-Host -Prompt " [?] Please enter your password" -AsSecureString
    $UT_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToBSTR($UT_PASSWORD))

    $SECURE_UT_PASSWORD = $UT_PASSWORD | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString

    if (-not $noSave) {
        Show-Info "Saving credentials..."
        Show-Info "Use -noSave flag to not save credentials."

        $newCredentialObject = @{
            default  = @($UT_USERNAME, $SECURE_UT_PASSWORD)
            accounts = @(, @($UT_USERNAME, $SECURE_UT_PASSWORD))
        }

        if (Save-CredentialObject -credentialObject $newCredentialObject -filePath $credentialFilePath) {
            Show-Success "Credentials saved successfully."
        }
        else {
            Show-Error "Failed to save credentials, but continuing with login..."
        }
    }
}


function Login-Acct ([string] $customAcctIp) {
    # Check if tesseract is installed
    if (-not (Get-Command tesseract -ErrorAction SilentlyContinue)) {
        Show-Error "Tesseract OCR is not installed or not found in PATH."
        Show-Info "Please install Tesseract OCR to use ACCT services."
        return @{
            Session  = $null
            Response = $null
            Ip       = $null
            Error    = "Login to ACCT failed due to missing OCR tool."
        }
    }

    if (-not $customAcctIp) {
        if (-not $acctIp) {
            $acctIp = Get-Ip -dnsServers $dnsServers -domain $acctDomain
            Write-Host
            Show-Success "IP: '$acctIp'"
        }
        $customAcctIp = $acctIp
    }

    $loginUrl = "https://$acctIp/IBSng/user/"

    # Send the login request
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
    $loginPage = Invoke-WebRequest -Uri $loginUrl -WebSession $session `
        -Headers @{
        Host = "$acctDomain"
    } -UseBasicParsing

    Show-Info "Downloading CAPTCHA image..."
    $captchaUrl = "https://$acctIp/IBSng/user/captcha.php"
    $captchaResponse = Invoke-WebRequest -UseBasicParsing -Uri $captchaUrl `
        -WebSession $session `
        -Headers @{
        Host                 = "$acctDomain"
        "Accept"             = "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
        "Accept-Encoding"    = "gzip, deflate, br, zstd"
        "Accept-Language"    = "en"
        "Cache-Control"      = "no-cache"
        "Pragma"             = "no-cache"
        "Referer"            = "https://acct.ut.ac.ir/IBSng/user/"
        "Sec-Fetch-Dest"     = "image"
        "Sec-Fetch-Mode"     = "no-cors"
        "Sec-Fetch-Site"     = "same-origin"
        "sec-ch-ua"          = "`"Chromium`";v=`"142`", `"Google Chrome`";v=`"142`", `"Not_A Brand`";v=`"99`""
        "sec-ch-ua-mobile"   = "?0"
        "sec-ch-ua-platform" = "`"Windows`""
    }
    $captchaBytes = $captchaResponse.Content
    $captchaFilePath = "$env:TEMP\ut_captcha_$(Get-Random).png"
    [System.IO.File]::WriteAllBytes($captchaFilePath, $captchaBytes)

    Show-Info "Solving CAPTCHA..."
    $captchaText = & tesseract $captchaFilePath stdout --oem 3 --psm 6 2>$null

    Show-Info "Cleaning up temporary CAPTCHA file..."
    Remove-Item -Path $captchaFilePath -Force -ErrorAction SilentlyContinue

    # Make sure to remove @ut.ac.ir from the username if it's included
    if ($UT_USERNAME -match "@ut\.ac\.ir$") {
        $UT_USERNAME = $UT_USERNAME -replace "@ut\.ac\.ir$", ""
    }
    # Prepare the data for the login request
    $data = @{
        normal_username = $UT_USERNAME
        normal_password = $UT_PASSWORD
        lang            = 'fa'
        captcha         = $captchaText.Trim()
        x               = 43
        y               = 6
    }

    $loginResponse = Invoke-WebRequest -Uri $loginUrl -Method "POST" `
        -Body $data -ContentType "application/x-www-form-urlencoded" -WebSession $session `
        -Headers @{
        Host = "$acctDomain"
    } -UseBasicParsing

    return @{
        Session  = $session
        Response = $loginResponse
        Ip       = $acctIp
        Error    = $null
    }
}


function Disconnect-Sessions {
    $loginData = Login-Acct
    if ($loginData.Error) {
        Show-Error $loginData.Error
        return
    }
    $session = $loginData.Session
    $loginResponse = $loginData.Response
    $acctIp = $loginData.Ip
    Show-Info "Trying to disconnect another session..."
    $disconnectUrl = "https://$acctIp/IBSng/user/home.php"
    if ($loginResponse.Content -match '/IBSng/user/bw_ajax.php\?ras_ip=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)&unique_id_val=([0-9a-zA-Z]+)') {
        $ras_ip = $Matches[1]
        # Send the kill request
        $payload = @{
            kill_me       = 1
            ras_ip        = $ras_ip
            unique_id_val = $Matches[2]
        }
        $response = Invoke-WebRequest -Uri $disconnectUrl -Method Post -WebSession $session `
            -Body $payload -ContentType "application/x-www-form-urlencoded" -Headers @{
            Host = "$acctDomain"
        } -UseBasicParsing
        if ($response.Content -match '<table class="Form_Main" width="580" border="0" cellspacing="0"') {
            Show-Success "Disconnected client $ras_ip!"
        }
        else {
            Show-Error "Failed to disconnect client $ras_ip!"
        }
    }
    else {
        Show-Error "Failed to disconnect a client."
    }
}


function Show-Remaining-Traffic {
    $loginData = Login-Acct
    if ($loginData.Error) {
        Show-Error $loginData.Error
        return
    }
    $loginResponse = $loginData.Response

    if ($loginResponse.Content -match '<td class="Form_Content_Row_Right_2Col_light">([0-9.,\-]+) UNITS</td>') {
        $value = [float]$Matches[1]
        $isNegative = $false
        if ($value -lt 0) {
            $isNegative = $true
            $value = - $value
        }
        $suffix = "MB", "GB", "TB", "PB", "EB", "ZB", "YB"
        $index = 0
        while ($value -gt 1kb) {
            $value = $value / 1kb
            $index++
        }
        if ($isNegative) {
            Show-Info "You have no traffic left!"
            Show-Info ("Your credit is -{0:N1} {1}!" -f $value, $suffix[$index])
        }
        else {
            Show-Info ("You have {0:N1} {1} traffic left!" -f $value, $suffix[$index])
        }
    }
    else {
        Show-Info $loginResponse.Content
    }
}

function Compare-SemanticVersion {
    param(
        [string]$version1,
        [string]$version2
    )

    # Parse version strings (e.g., "1.2.3" or "1.2.3-beta")
    $v1Parts = $version1 -split '-'
    $v2Parts = $version2 -split '-'

    $v1Numbers = $v1Parts[0] -split '\.' | ForEach-Object { [int]$_ }
    $v2Numbers = $v2Parts[0] -split '\.' | ForEach-Object { [int]$_ }

    # Pad arrays to same length
    $maxLength = [Math]::Max($v1Numbers.Length, $v2Numbers.Length)
    while ($v1Numbers.Length -lt $maxLength) { $v1Numbers += 0 }
    while ($v2Numbers.Length -lt $maxLength) { $v2Numbers += 0 }

    # Compare each part
    for ($i = 0; $i -lt $maxLength; $i++) {
        if ($v1Numbers[$i] -lt $v2Numbers[$i]) {
            return -1  # version1 is older
        }
        elseif ($v1Numbers[$i] -gt $v2Numbers[$i]) {
            return 1   # version1 is newer
        }
    }

    # If base versions are equal, check pre-release tags
    if ($v1Parts.Length -gt 1 -and $v2Parts.Length -eq 1) {
        return -1  # version1 is pre-release, version2 is stable (version2 is newer)
    }
    elseif ($v1Parts.Length -eq 1 -and $v2Parts.Length -gt 1) {
        return 1   # version1 is stable, version2 is pre-release (version1 is newer)
    }

    return 0  # versions are equal
}

function Check-Updates {
    try {
        $latestReleaseUrl = "https://api.github.com/repos/MPCodeWriter21/UT-Internet/releases/latest"

        # Set TLS to 1.2 for GitHub API
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        $response = Invoke-RestMethod -Uri $latestReleaseUrl -Method Get -ErrorAction Stop -TimeoutSec 5

        $latestVersion = $response.tag_name -replace '^v', ''
        $currentVersionClean = $currentVersion -replace '^v', ''

        # Compare versions: -1 if current < latest, 0 if equal, 1 if current > latest
        $comparison = Compare-SemanticVersion -version1 $currentVersionClean -version2 $latestVersion

        if ($comparison -lt 0) {
            Write-Host
            Write-Host -ForegroundColor Yellow '  =========================================================================== '
            Write-Host -ForegroundColor Yellow " |" -NoNewline
            Write-Host -ForegroundColor Green    "                            UPDATE AVAILABLE!                              " -NoNewline
            Write-Host -ForegroundColor Yellow                                                                              "|"
            Write-Host -ForegroundColor Yellow "  =========================================================================== "
            Write-Host -ForegroundColor Yellow " |" -NoNewline
            Write-Host -ForegroundColor White "  Current Version: " -NoNewline
            Write-Host -ForegroundColor Cyan "$currentVersionClean" -NoNewline
            Write-Host -ForegroundColor White (" " * (56 - $currentVersionClean.Length)) -NoNewline
            Write-Host -ForegroundColor Yellow "|"
            Write-Host -ForegroundColor Yellow " |" -NoNewline
            Write-Host -ForegroundColor White "  Latest Version:  " -NoNewline
            Write-Host -ForegroundColor Green "$latestVersion" -NoNewline
            Write-Host -ForegroundColor White (" " * (56 - $latestVersion.Length)) -NoNewline
            Write-Host -ForegroundColor Yellow "|"
            Write-Host -ForegroundColor Yellow "  ============================================================================ "
            Write-Host -ForegroundColor Yellow " |" -NoNewline
            Write-Host -ForegroundColor White "  Download: " -NoNewline
            Write-Host -ForegroundColor Cyan "https://github.com/MPCodeWriter21/UT-Internet/releases/latest" -NoNewline
            Write-Host -ForegroundColor White "  " -NoNewline
            Write-Host -ForegroundColor Yellow "|"
            Write-Host -ForegroundColor Yellow "  ============================================================================ "

            if ($response.body) {
                # Extract content between "### 📝 What's Changed" and "### ⚙️ Features"
                $bodyLines = $response.body -split "`n"
                $startIndex = -1
                $endIndex = -1

                for ($i = 0; $i -lt $bodyLines.Length; $i++) {
                    if ($bodyLines[$i] -match "###.*What's Changed") {
                        $startIndex = $i + 1
                    }
                    elseif ($startIndex -ge 0 -and $bodyLines[$i] -match "###.*Features") {
                        $endIndex = $i
                        break
                    }
                }

                if ($startIndex -ge 0) {
                    if ($endIndex -lt 0) { $endIndex = $bodyLines.Length }
                    $releaseNotes = $bodyLines[$startIndex..($endIndex - 1)] | Where-Object { $_.Trim() -ne "" }

                    if ($releaseNotes.Count -gt 0) {
                        Write-Host -ForegroundColor Yellow " |" -NoNewline
                        Write-Host -ForegroundColor White "  What's Changed:" -NoNewline
                        Write-Host -ForegroundColor White (" " * 58) -NoNewline
                        Write-Host -ForegroundColor Yellow "|"

                        foreach ($line in $releaseNotes) {
                            $truncated = if ($line.Length -gt 71) { $line.Substring(0, 68) + "..." } else { $line }
                            Write-Host -ForegroundColor Yellow " |" -NoNewline
                            Write-Host -ForegroundColor Gray "  $truncated" -NoNewline
                            Write-Host -ForegroundColor White (" " * (73 - $truncated.Length)) -NoNewline
                            Write-Host -ForegroundColor Yellow "|"
                        }
                    }
                }
            }

            Write-Host -ForegroundColor Yellow "  =========================================================================== "
            Show-Info "Use '-noUpdateCheck' flag to disable update notifications."
        }
    }
    catch {
        Write-Host -ForegroundColor DarkGray " [i] Could not check for updates: $($_.Exception.Message)"
    }
}


function Login-Device {
    Write-Host
    Show-Info "Logging in..."

    # Prepare the data for the login request
    $data = @{
        username  = $UT_USERNAME
        password  = $UT_PASSWORD
        magic     = $magicValue
        '4Tredir' = 'https://internet.ut.ac.ir:1003/portal?'
    }

    # Send the login request
    $response = Invoke-WebRequest -Uri "https://$ip`:1003" -Method Post -Body $data -ContentType "application/x-www-form-urlencoded" -Headers @{
        Host = "$internetDomain`:1003"
    } -UseBasicParsing

    # Check the response for a successful login
    if ($response.Content -match 'window.location="https://internet.ut.ac.ir:1003/portal\?.*";') {
        Show-Success "Successfully logged in!"
        if (-not $noRemainingTraffic) {
            Show-Remaining-Traffic
        }
        if (-not $noUpdateCheck) {
            Check-Updates
        }
    }
    else {
        Show-Error "Failed to login for some reason..."
        if ($response.Content -match '<input type="hidden" name="4Tredir" value="https://internet.ut.ac.ir:1003/portal\?">') {
            $title = " [!] Try to disconnect other sessions?"
            $question = " [i] This login failure might be caused by too many sessions being logged in using your credentials.`n"
            $question += " [?] Do you want to try to disconnect other sessions?"
            $choices = "&Yes", "&No"

            $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
            if ($decision -eq 0) {
                Disconnect-Sessions
                Login-Device
            }
            else {
                Show-Error "Failed to login."
            }
        }
    }
}

Login-Device

pause
