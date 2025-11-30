#######################################################################################################################
#
# Author: Nayrk
# Date: 12/28/2018
# Last Updated: 11/10/2025 (login flow updated to Blink OAuth like blinkpy, with token refresh)
# Purpose: To download all Blink videos locally to the PC. Existing videos will be skipped.
# Output: All Blink videos downloaded in the following directory format.
#         Default Location Desktop - "C:\temp\Blink"
#         Sub-Folders - Blink --> Home Network Name --> Camera Name #1
#                                                   --> Camera Name #2
#
# Notes: You can change anything below this section.
# Credits: https://github.com/MattTW/BlinkMonitorProtocol
# Fixed By: colinreid89 on 05/15/2020
# Fixed By: tyuhas on 02/03/2021
# Fixed By: ttteee90 on 03/19/2021
# Updates: Added infinite loop to re-run every 30 minutes as a keep alive to bypass pin prompt from Blink/Amazon
#          03/22/2021 - Cleaned up the code and added more debug messages. Added try/catch on invalid pin.
#          11/10/2025 - Updated login to use OAuth /oauth/token + 2FA header and tier_info, added token refresh.
#######################################################################################################################

# Change saveDirectory directory if you want the Blink Files to be saved somewhere else, default is user Desktop
#$saveDirectory = "C:\Users\$env:UserName\Desktop"
$saveDirectory = "C:\temp\Blink"

# Blink Credentials. Please fill in!
# Please keep the quotation marks "
$email = "Your Email Here"
$password = "Your Password Here "

# Legacy: Blink's API Server (no longer used for login, but kept for reference)
$blinkAPIServer = 'rest-prod.immedia-semi.com'

# New OAuth endpoints (mirrors blinkpy constants)
$oauthBaseUrl = "https://api.oauth.blink.com"
$loginUrl     = "$oauthBaseUrl/oauth/token"
$tierInfoUrl  = "https://rest-prod.immedia-semi.com/api/v1/users/tier_info"

#######################################################################################################################
#
# Do not change anything below unless you know what you are doing or you want to...
#
#######################################################################################################################

if($email -eq "Your Email Here") { Write-Host 'Please enter your email by modifying the line: $email = "Your Email Here"'; pause; exit;}
if($password -eq "Your Password Here") { Write-Host 'Please enter your password by modifying the line: $password = "Your Password Here"'; pause; exit;}

# Common headers used for OAuth login / tier_info
$oauthHeadersBase = @{
    "Content-Type" = "application/x-www-form-urlencoded"
    "User-Agent"   = "27.0ANDROID_28373244"  # from blinkpy DEFAULT_USER_AGENT
    "hardware_id"  = "Blinkpy"              # from blinkpy DEVICE_ID (can be any stable ID)
}

# ---- Helper: refresh OAuth token when expired ----
function Invoke-BlinkOAuthRefresh {
    param(
        [string]$RefreshToken
    )

    $refreshBody = @{
        "grant_type"    = "refresh_token"
        "refresh_token" = $RefreshToken
        "client_id"     = "android"
    }

    Write-Host "Refreshing OAuth access token..."

    try {
        $resp = Invoke-RestMethod -UseBasicParsing `
            -Uri "https://api.oauth.blink.com/oauth/token" `
            -Method Post `
            -Headers $oauthHeadersBase `
            -Body $refreshBody

        if ($resp.access_token) {
            Write-Host "Token refreshed successfully."
            return $resp
        } else {
            Write-Host "Refresh failed: no access_token returned."
            return $null
        }
    } catch {
        Write-Host "Refresh request failed: $($_.Exception.Message)"
        return $null
    }
}

# ---- HELPER: Perform initial OAuth login (password) with optional 2FA ----
function Invoke-BlinkOAuthLogin {
    param(
        [string]$Username,
        [string]$Password
    )

    # Form data used by blinkpy: username, client_id, scope, grant_type=password, password
    $loginBody = @{
        "username"   = $Username
        "password"   = $Password
        "client_id"  = "android"
        "scope"      = "client"
        "grant_type" = "password"
    }

    Write-Host "Authenticating with Blink OAuth..."

    # First attempt (may return 412 if 2FA required)
    try {
        $resp = Invoke-RestMethod -UseBasicParsing -Uri $loginUrl -Method Post -Headers $oauthHeadersBase -Body $loginBody
        return $resp
    } catch {
        $statusCode = $null
        try { $statusCode = $_.Exception.Response.StatusCode.value__ } catch {}

        if ($statusCode -eq 412) {
            Write-Host "Two-factor authentication required. Check your email or SMS for the Blink code."
            $pin = Read-Host -Prompt 'Input 2FA PIN'

            # Add 2fa-code header like blinkpy does when login_data contains "2fa_code"
            $headersWith2fa = $oauthHeadersBase.Clone()
            $headersWith2fa["2fa-code"] = $pin

            try {
                $resp = Invoke-RestMethod -UseBasicParsing -Uri $loginUrl -Method Post -Headers $headersWith2fa -Body $loginBody
                return $resp
            } catch {
                Write-Host "Login failed even after supplying 2FA code. Status: $statusCode"
                throw
            }
        } else {
            Write-Host "Login failed. HTTP status code: $statusCode"
            throw
        }
    }
}

# ---- Perform login and tier lookup (Blink.start + Auth.refresh_tokens + tier_info) ----
$loginResponse = Invoke-BlinkOAuthLogin -Username $email -Password $password

if (-not $loginResponse) {
    Write-Host "Invalid credentials or failed OAuth login. Please verify email and password."
    pause
    exit
}

Write-Host "Authenticated with Blink successfully (OAuth)."

# Extract OAuth tokens
$accessToken  = $loginResponse.access_token
$refreshToken = $loginResponse.refresh_token
$expiresIn    = $loginResponse.expires_in

# Rough expiry timestamp (we will actually refresh when needed)
$tokenExpiresAt = (Get-Date).AddSeconds($expiresIn - 60)

# Get tier info (region + account_id), like blinkpy Auth.get_tier_info / extract_tier_info
$tierHeaders = @{
    "Content-Type" = "application/x-www-form-urlencoded"
    "User-Agent"   = "27.0ANDROID_28373244"
    "Authorization" = "Bearer $accessToken"
}

try {
    $tierInfo = Invoke-RestMethod -UseBasicParsing -Uri $tierInfoUrl -Method Get -Headers $tierHeaders
} catch {
    Write-Host "Failed to retrieve tier_info from Blink."
    pause
    exit
}

# tier_info.tier is usually something like "u006" and the real hostname is "rest-u006.immedia-semi.com"
$regionCode = $tierInfo.tier        # e.g. "u006" or "rest-u017"
$accountID  = $tierInfo.account_id

if (-not $regionCode -or -not $accountID) {
    Write-Host "tier_info response is missing region/account_id; cannot continue."
    pause
    exit
}

# Ensure we have the full hostname prefix "rest-"
if ($regionCode -like "rest-*") {
    $regionHost = $regionCode
} else {
    $regionHost = "rest-$regionCode"
}

# Base URL used for all subsequent requests (matches blinkpy's base_url)
$baseUrl = "https://$regionHost.immedia-semi.com"

Write-Host "Region code: $regionCode"
Write-Host "Region host: $regionHost"
Write-Host "Account ID: $accountID"
Write-Host "Base URL: $baseUrl"
Write-Host ""

# Headers to send to Blink's server after authentication with our Bearer token (replaces TOKEN_AUTH)
$authHeaders = @{
    "Authorization" = "Bearer $accessToken"
}

while (1) {
    Write-Host "Script will re-run every 30 minutes as a keep alive to Blink server."

    # Refresh token if it will expire within the next 10 minutes
    if ((New-TimeSpan -Start (Get-Date) -End $tokenExpiresAt).TotalMinutes -lt 10) {
        $newTokens = Invoke-BlinkOAuthRefresh -RefreshToken $refreshToken
        if ($newTokens) {
            $accessToken      = $newTokens.access_token
            $refreshToken     = $newTokens.refresh_token
            $expiresIn        = $newTokens.expires_in
            $tokenExpiresAt   = (Get-Date).AddSeconds($expiresIn - 60)
            $authHeaders["Authorization"] = "Bearer $accessToken"
            Write-Host "Access token refreshed early. Next expiry at $tokenExpiresAt"
        } else {
            Write-Host "Unable to refresh access token. Will retry next loop."
        }
    }

    # --- SAFETY: verify we still have a valid access token ---
    if ([string]::IsNullOrWhiteSpace($accessToken)) {
        Write-Host "ERROR: Access token missing or invalid. Stopping script for safety."
        break
    }

        # --- Get homescreen, which includes full thumbnail paths per camera ---
    $homeUri = "$baseUrl/api/v3/accounts/$accountID/homescreen"
    try {
        $homescreen = Invoke-RestMethod -UseBasicParsing -Uri $homeUri -Method Get -Headers $authHeaders
    } catch {
        Write-Host "Failed to load homescreen. Error: $($_.Exception.Message)"
        # You can choose to continue or break; here we'll continue the loop but skip thumbnails this cycle.
        $homescreen = $null
    }

    # Build a lookup of camera_id -> thumbnail path/url from homescreen
    $cameraThumbs = @{}
    if ($homescreen -and $homescreen.cameras) {
        foreach ($hc in $homescreen.cameras) {
            if ($hc.PSObject.Properties['id'] -and $hc.PSObject.Properties['thumbnail']) {
                $cameraThumbs[$hc.id] = [string]$hc.thumbnail
            }
        }
    }

    # Get list of networks / cameras (usage endpoint)
    $uri = "$baseUrl/api/v1/camera/usage"

    $sync_units = Invoke-RestMethod -UseBasicParsing $uri -Method Get -Headers $authHeaders

    foreach($sync_unit in $sync_units.networks) {
        $network_id   = $sync_unit.network_id
        $networkName  = $sync_unit.name

        foreach($camera in $sync_unit.cameras) {
            $cameraName = $camera.name
            $cameraId   = $camera.id
            $uri        = "$baseUrl/network/$network_id/camera/$cameraId"

            $cameraInfo = Invoke-RestMethod -UseBasicParsing $uri -Method Get -Headers $authHeaders

            # --- Resolve thumbnail path from homescreen lookup ---
            $rawThumbFromHome = $null
            if ($cameraThumbs.ContainsKey($cameraId)) {
                $rawThumbFromHome = $cameraThumbs[$cameraId]
            }

            if (-not $rawThumbFromHome) {
                Write-Host "No homescreen thumbnail for $cameraName in $networkName. Skipping thumbnail."
            } else {
                # Build full URL from homescreen thumbnail value:
                #  - If it is already a full URL (http...), use as-is
                #  - If it is a path (/api/...), prefix with baseUrl
                if ($rawThumbFromHome -like 'http*') {
                    $thumbURL = $rawThumbFromHome
                } elseif ($rawThumbFromHome.StartsWith('/')) {
                    $thumbURL = "$baseUrl$rawThumbFromHome"
                } else {
                    $thumbURL = "$baseUrl/$rawThumbFromHome"
                }

                # Create Blink Directory to store videos if it does not exist
                $path = "$saveDirectory\Blink\$networkName\$cameraName"
                if (-not (Test-Path $path)) {
                    New-Item -ItemType Directory -Path $path | Out-Null
                }

                # Extract timestamp from the thumbnail URL (ts=XXXXXXXX) for filename
                $tsMatch = [regex]::Match($thumbURL, 'ts=(\d+)')
                if ($tsMatch.Success) {
                    $timestamp = $tsMatch.Groups[1].Value
                } else {
                    # If for some reason there's no ts in homescreen thumbnail, fall back to camera_status.thumbnail
                    $rawStatusThumb = [string]$cameraInfo.camera_status.thumbnail
                    if ($rawStatusThumb -match '^\d+$') {
                        $timestamp = $rawStatusThumb
                    } else {
                        $timestamp = [int][double]::Parse((Get-Date -UFormat %s))
                    }
                }

                # Build filename like thumbnail_1720655252.jpg
                $thumbPath = Join-Path $path ("thumbnail_{0}.jpg" -f $timestamp)

                # Skip if already downloaded
                if (-not (Test-Path $thumbPath)) {
                    Write-Host "Downloading thumbnail for $cameraName camera in $networkName."
                    try {
                        Invoke-RestMethod -UseBasicParsing -Uri $thumbURL -Method Get -Headers $authHeaders -OutFile $thumbPath -ErrorAction Stop
                    } catch {
                        $httpCode = $null
                        try { $httpCode = $_.Exception.Response.StatusCode.value__ } catch {}
                        if ($httpCode -eq 404) {
                            Write-Host "Thumbnail not found (404) for $cameraName in $networkName. URL: $thumbURL"
                        } else {
                            Write-Host "Error downloading thumbnail for $cameraName in $networkName. HTTP: $httpCode URL: $thumbURL"
                        }
                    }
                }
            }
        }
    }

    $pageNum = 1

    # Continue to download videos from each page until all are downloaded
    while (1) {
        # Same endpoint pattern blinkpy uses in request_videos()
        $uri = "$baseUrl/api/v1/accounts/$accountID/media/changed?since=2015-04-19T23:11:20+0000&page=$pageNum"

        # Get the list of video clip information from each page from Blink
        try {
            $response = Invoke-RestMethod -UseBasicParsing -Uri $uri -Method Get -Headers $authHeaders -ErrorAction Stop
        } catch {
            $httpCode = $null
            try { $httpCode = $_.Exception.Response.StatusCode.value__ } catch {}

            if ($httpCode -eq 401) {
                Write-Host "Got 401 (Unauthorized) when listing media. Refreshing token and retrying once..."

                $newTokens = Invoke-BlinkOAuthRefresh -RefreshToken $refreshToken
                if ($newTokens) {
                    $accessToken      = $newTokens.access_token
                    $refreshToken     = $newTokens.refresh_token
                    $expiresIn        = $newTokens.expires_in
                    $tokenExpiresAt   = (Get-Date).AddSeconds($expiresIn - 60)
                    $authHeaders["Authorization"] = "Bearer $accessToken"

                    # retry once
                    try {
                        $response = Invoke-RestMethod -UseBasicParsing -Uri $uri -Method Get -Headers $authHeaders -ErrorAction Stop
                    } catch {
                        Write-Host "Media list retry after refresh also failed with 401. Stopping script."
                        break 2   # break out of both the media-pages loop and the outer while(1)
                    }
                } else {
                    Write-Host "Token refresh failed after 401. Stopping script."
                    break 2
                }
            } else {
                Write-Host "Error listing media. HTTP: $httpCode"
                break 2
            }
        }

        # No more videos to download, exit from loop
        if (-not $response.media) {
            break
        }

        # Go through each video information and get the download link and relevant information
        foreach($video in $response.media) {
            # Video clip information
            $address   = $video.media
            $timestamp = $video.created_at
            $network   = $video.network_name
            $camera    = $video.device_name
            $camera_id = $video.camera_id
            $deleted   = $video.deleted
            if ($deleted -eq "True") {
                continue
            }

            # Get video timestamp in local time
            $videoTime = Get-Date -Date $timestamp -Format "yyyy-MM-dd_HH-mm-ss"

            # Download address of video clip
            $videoURL = "$baseUrl$address"

            # Download video if it is new
            $path = "$saveDirectory\Blink\$network\$camera"
            if (-not (Test-Path $path)) {
                New-Item -ItemType Directory -Path $path | Out-Null
            }
            $videoPath = "$path\$videoTime.mp4"
            if (-not (Test-Path $videoPath)) {
                try {
                    Invoke-RestMethod -UseBasicParsing $videoURL -Method Get -Headers $authHeaders -OutFile $videoPath
                    Write-Host "Downloading video for $camera camera in $network."
                } catch {
                    # Minimal logging to prevent spam when video file no longer exists
                    $httpCode = $null
                    try { $httpCode = $_.Exception.Response.StatusCode.value__ } catch {}
                    if ($httpCode -ne 404 -and $httpCode) {
                        Write-Host "Download error HTTP $httpCode for $videoURL"
                    }
                }
            }
        }

        $pageNum += 1
    }

    Write-Host "All new videos and thumbnails downloaded to $saveDirectory\Blink\"
    Write-Host "Sleeping for 30 minutes before next run..."
    # Sleep for 30 minutes
    Start-Sleep -Seconds 1800
}