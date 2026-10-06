# ============================================
# AD Automation Agent - Onboard + Offboard + Reactivate
# With API Key authentication
# Runs on/near the Domain Controller. Polls the backend; never accepts inbound connections.
# ============================================

# 1. Import Active Directory module
Import-Module ActiveDirectory

# 2. Configuration
# Everything environment-specific (backend URL, API key, domain, OUs, groups)
# lives in config.json next to this script. Copy config.example.json -> config.json.
$BasePath     = $PSScriptRoot
$ConfigFile   = Join-Path $BasePath "config.json"
$LogFile      = Join-Path $BasePath "log.txt"
$PollInterval = 10   # seconds

# 3. Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Line = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $Line
    Write-Host $Line
}

# 4. Load config
if (-not (Test-Path $ConfigFile)) {
    Write-Log "Config file not found: $ConfigFile" "ERROR"
    exit 1
}
$Config = Get-Content $ConfigFile -Raw | ConvertFrom-Json

$BackendUrl = $Config.backend_url
if (-not $BackendUrl) {
    Write-Log "backend_url missing in config.json" "ERROR"
    exit 1
}
$BackendUrl = $BackendUrl.TrimEnd('/')

# 5. API Key setup
$ApiKey = $Config.api_key
if (-not $ApiKey) {
    Write-Log "API Key missing in config.json" "ERROR"
    exit 1
}
$Headers = @{ "X-API-Key" = $ApiKey }

Write-Log "Agent started. Backend: $BackendUrl"
Write-Log "API Key loaded (length: $($ApiKey.Length))"

# ============================================
# 6. ONBOARDING
# ============================================
function Invoke-Onboard {
    param($Data)

    Write-Log "Onboarding user: $($Data.username)"

    $Dept = $Data.department
    if (-not $Config.departments.$Dept) {
        throw "Unknown department: $Dept"
    }

    $OUPath    = $Config.departments.$Dept.ou
    $GroupName = $Config.departments.$Dept.group

    $Existing = Get-ADUser -Filter "SamAccountName -eq '$($Data.username)'" -ErrorAction SilentlyContinue
    if ($Existing) {
        throw "User already exists: $($Data.username)"
    }

    $FullName = "$($Data.first_name) $($Data.last_name)"
    $UPN      = "$($Data.username)@$($Config.domain)"
    $SecurePass = ConvertTo-SecureString $Data.password -AsPlainText -Force

    New-ADUser `
        -Name $FullName `
        -GivenName $Data.first_name `
        -Surname $Data.last_name `
        -SamAccountName $Data.username `
        -UserPrincipalName $UPN `
        -Path $OUPath `
        -AccountPassword $SecurePass `
        -ChangePasswordAtLogon $true `
        -Enabled $true

    Write-Log "User created: $($Data.username)"

    Add-ADGroupMember -Identity $GroupName -Members $Data.username
    Write-Log "User added to group: $GroupName"

    return @{
        status   = "done"
        username = $Data.username
        message  = "User $($Data.username) created in $Dept"
    }
}

# ============================================
# 7. OFFBOARDING
# ============================================
function Invoke-Offboard {
    param($Data)

    Write-Log "Offboarding user: $($Data.username)"

    $User = Get-ADUser -Filter "SamAccountName -eq '$($Data.username)'" -Properties MemberOf -ErrorAction SilentlyContinue
    if (-not $User) {
        throw "User not found: $($Data.username)"
    }

    if (-not $User.Enabled) {
        throw "User already disabled: $($Data.username)"
    }

    $Groups = $User.MemberOf
    foreach ($groupDN in $Groups) {
        try {
            Remove-ADGroupMember -Identity $groupDN -Members $Data.username -Confirm:$false
            Write-Log "Removed from group: $groupDN"
        }
        catch {
            Write-Log "Failed to remove from $groupDN : $_" "WARN"
        }
    }

    Disable-ADAccount -Identity $Data.username
    Write-Log "User disabled: $($Data.username)"

    return @{
        status  = "done"
        message = "User $($Data.username) disabled and removed from groups"
    }
}

# ============================================
# 8. REACTIVATE
# ============================================
function Invoke-Reactivate {
    param($Data)

    Write-Log "Reactivating user: $($Data.username)"

    $User = Get-ADUser -Filter "SamAccountName -eq '$($Data.username)'" -Properties MemberOf -ErrorAction SilentlyContinue
    if (-not $User) {
        throw "User not found: $($Data.username)"
    }

    if ($User.Enabled) {
        throw "User already enabled: $($Data.username)"
    }

    Enable-ADAccount -Identity $Data.username
    Write-Log "User enabled: $($Data.username)"

    # Try to add back to appropriate group based on OU
    try {
        $UserDN = $User.DistinguishedName
        $OUPath = ($UserDN -split ',', 2)[1]

        $MatchedDept = $null
        foreach ($dept in $Config.departments.PSObject.Properties) {
            if ($dept.Value.ou -eq $OUPath) {
                $MatchedDept = $dept.Name
                break
            }
        }

        if ($MatchedDept) {
            $GroupName = $Config.departments.$MatchedDept.group
            Add-ADGroupMember -Identity $GroupName -Members $Data.username
            Write-Log "User added back to group: $GroupName (dept: $MatchedDept)"
        } else {
            Write-Log "Could not determine department from OU: $OUPath" "WARN"
        }
    }
    catch {
        Write-Log "Failed to add back to group: $_" "WARN"
    }

    return @{
        status  = "done"
        message = "User $($Data.username) reactivated"
    }
}

# ============================================
# 9. Router
# ============================================
function Invoke-Request {
    param($Request)

    $ReqId  = $Request.id
    $Action = $Request.action
    if (-not $Action) { $Action = "onboard" }

    Write-Log "Processing request #$ReqId (action: $Action)"

    try {
        switch ($Action) {
            "onboard" {
                $Result = Invoke-Onboard -Data $Request
            }
            "offboard" {
                $Result = Invoke-Offboard -Data $Request
            }
            "reactivate" {
                $Result = Invoke-Reactivate -Data $Request
            }
            default {
                throw "Unknown action: $Action"
            }
        }
    }
    catch {
        # The backend stores the "error" field in the audit log
        $Result = @{
            status   = "failed"
            username = $Request.username
            error    = $_.ToString()
        }
        Write-Log "Failed: $_" "ERROR"
    }

    # Send result back (with API Key)
    try {
        $Body = $Result | ConvertTo-Json
        Invoke-RestMethod -Uri "$BackendUrl/api/result/$ReqId" -Method POST -Body $Body -ContentType "application/json" -Headers $Headers | Out-Null
        Write-Log "Result sent for request #$ReqId"
    }
    catch {
        Write-Log "Failed to send result: $_" "ERROR"
    }
}

# ============================================
# 10. Main polling loop
# ============================================
Write-Log "===== Polling started ====="

while ($true) {
    try {
        $Response = Invoke-RestMethod -Uri "$BackendUrl/api/pending" -Method GET -TimeoutSec 5 -Headers $Headers

        if ($Response.count -gt 0) {
            Write-Log "Found $($Response.count) pending request(s)"
            foreach ($req in $Response.requests) {
                Invoke-Request -Request $req
            }
        }
    }
    catch {
        Write-Log "Polling error: $_" "ERROR"
    }

    Start-Sleep -Seconds $PollInterval
}
