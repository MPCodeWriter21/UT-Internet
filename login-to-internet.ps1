# ==================================================================================== #
#                      Copyright (c) 2024-2025 Mehrad Pooryoussof                      #
# ==================================================================================== #
# - What is this script?                                                               #
# + This script is a PowerShell script that logs you into the UT network.              #
#                                                                                      #
# - What are its features?                                                             #
# + It can save your credentials for future use.                                       #
# + You can reset your saved credentials.                                              #
# + You can choose not to save your credentials.                                       #
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
    [switch]$noRemainingTraffic = $false,
    [switch]$help = $false,
    [switch]$version = $false
)

Write-Host -ForegroundColor Yellow "=========================================================================="
Write-Host -ForegroundColor White  "        Copyright (C) 2024-2025 CodeWriter21 - Mehrad Pooryoussof         "
Write-Host -ForegroundColor Yellow "=========================================================================="
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

if ($help) {
    Show-Info "This script logs you into the UT network."
    Write-Host
    Show-Info "Usage: SCRIPT_NAME [-reset] [-noSave] [-noRemainingTraffic] [-help]"
    Show-Info "Options:"
    Show-Info "  -reset              Reset saved credentials."
    Show-Info "  -noSave             Do not save credentials."
    Show-Info "  -noRemainingTraffic Do not show remaining traffic."
    Show-Info "  -help               Show this help message."
    Show-Info "  -version            Show the version of the script."
    exit 0
}

if ($version) {
    Show-Info "Version: 1.0.0"
    exit 0
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
            if (-not $noRemainingTraffic) {
                Show-Remaining-Traffic
            }
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

Write-Host
$savedCredentials = $false
$credentialFilePath = "$HOME\.ut.net.creds"

if ($reset) {
    Remove-Item -Path $credentialFilePath -Force -ErrorAction SilentlyContinue
}

[string]$credentialData = Get-Content -ErrorAction SilentlyContinue $credentialFilePath

if ($credentialData) {
    try {
        Show-Success "Found saved credentials."
        Show-Info "Use '-reset' flag to enter new credentials."
        $credentialObject = ConvertFrom-Json $credentialData
        [string]$UT_USERNAME = $credentialObject[0]
        [SecureString]$SECURE_UT_PASSWORD = $credentialObject[1] | ConvertTo-SecureString -ErrorAction Stop
        $UT_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringUni([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SECURE_UT_PASSWORD))
        $savedCredentials = $true
    }
    catch {
        Show-Error "Failed to use the saved credentials."
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
        $credentialData = ConvertTo-Json $UT_USERNAME, $SECURE_UT_PASSWORD

        # Save Content to file
        $credentialData | Set-Content -Path $credentialFilePath

        $credentialFile = gci -Force $credentialFilePath
        $credentialFile.Attributes += "Hidden, System"
        $credentialFile.Attributes -= "Archive"
    }
}


function Login-Acct ([string] $customAcctIp) {
    if (-not $customAcctIp) {
        if (-not $acctIp) {
            $acctIp = Get-Ip -dnsServers $dnsServers -domain $acctDomain 
            Write-Host
            Show-Success "IP: '$acctIp'"
        }
        $customAcctIp = $acctIp
    }

    $loginUrl = "https://$acctIp/IBSng/user/"

    # Prepare the data for the login request
    $data = @{
        normal_username = $UT_USERNAME
        normal_password = $UT_PASSWORD
        lang            = 'fa'
        x               = 22
        y               = 14
    }

    # Send the login request
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
    $loginPage = Invoke-WebRequest -Uri $loginUrl -WebSession $session `
        -Headers @{
        Host = "$acctDomain"
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
    }
}


function Disconnect-Sessions {
    $loginData = Login-Acct
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
    $loginResponse = (Login-Acct).Response

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


function Login-Device {
    Write-Host
    Show-Info "Logging in..."

    # Prepare the data for the login request
    $data = @{
        username  = $UT_USERNAME
        password  = $UT_PASSWORD
        magic     = Get-Magic
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
            Write-Host
            Show-Remaining-Traffic
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