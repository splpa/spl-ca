# CA Worker Script
# Runs on a schedule (e.g. every minute via Task Scheduler)
# Processes CSR requests queued by the Node.js API
# Requires: sqlite3.exe on PATH or in same directory

param(
    [string]$DbPath = "C:\Apps\Apps\spl-ca\Certificates.db",
    [string]$CAConfig = "SPLROOTCA\PathologyAssociates-SPLROOTCA-CA",
    [string]$TempDir = "C:\Apps\Apps\spl-ca\temp"
)

# Ensure temp directory exists
if (-not (Test-Path $TempDir)) {
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
}

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp] $Message"
}

function Invoke-Sqlite {
    param([string]$Query)
    $result = sqlite3 $DbPath -header -separator "|" $Query 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Log "SQLite error: $result"
        return $null
    }
    return $result
}

function Get-PendingSubmissions {
    $rows = Invoke-Sqlite "SELECT id, uuid, csrText FROM CsrRequests WHERE status = 'pending_submit';"
    if (-not $rows -or $rows.Count -eq 0) { return @() }
    # Skip header row
    $data = @()
    $lines = $rows -split "`n" | Where-Object { $_ -ne "" }
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $parts = $lines[$i] -split "\|", 3
        if ($parts.Count -ge 3) {
            $data += @{
                id      = $parts[0]
                uuid    = $parts[1]
                csrText = $parts[2]
            }
        }
    }
    return $data
}

function Get-SubmittedRequests {
    $rows = Invoke-Sqlite "SELECT id, uuid, requestId FROM CsrRequests WHERE status = 'submitted' AND requestId > 0;"
    if (-not $rows -or $rows.Count -eq 0) { return @() }
    $data = @()
    $lines = $rows -split "`n" | Where-Object { $_ -ne "" }
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $parts = $lines[$i] -split "\|"
        if ($parts.Count -ge 3) {
            $data += @{
                id        = $parts[0]
                uuid      = $parts[1]
                requestId = $parts[2]
            }
        }
    }
    return $data
}

function Update-RequestStatus {
    param(
        [string]$Id,
        [string]$Status,
        [int]$RequestId = -1,
        [string]$B64Cert = "",
        [string]$Error = ""
    )
    $now = [long](([datetime]::UtcNow - [datetime]'1970-01-01').TotalMilliseconds)
    $nowStr = (Get-Date).ToString("M/d/yyyy h:mmtt")
    # Escape single quotes in values
    $Error = $Error -replace "'", "''"
    $B64Cert = $B64Cert -replace "'", "''"
    $query = "UPDATE CsrRequests SET status = '$Status', requestId = $RequestId, b64Cert = '$B64Cert', error = '$Error', updated = $now, updatedStr = '$nowStr' WHERE id = $Id;"
    Invoke-Sqlite $query | Out-Null
}

function Submit-CSR {
    param([hashtable]$Request)
    $reqFile = Join-Path $TempDir "$($Request.uuid).req"
    try {
        # Write CSR to temp file
        $Request.csrText | Out-File -FilePath $reqFile -Encoding ascii -NoNewline
        # Submit to CA
        $result = & certreq -submit -config $CAConfig $reqFile 2>&1 | Out-String
        # Clean up temp file
        Remove-Item $reqFile -Force -ErrorAction SilentlyContinue
        if ($result -match "RequestId:\s*(\d+)") {
            $requestId = [int]$Matches[1]
            Write-Log "CSR $($Request.uuid) submitted, RequestId: $requestId"
            Update-RequestStatus -Id $Request.id -Status "submitted" -RequestId $requestId
            return $true
        }
        else {
            Write-Log "CSR $($Request.uuid) submission failed: $result"
            Update-RequestStatus -Id $Request.id -Status "failed" -Error $result
            return $false
        }
    }
    catch {
        Remove-Item $reqFile -Force -ErrorAction SilentlyContinue
        Write-Log "CSR $($Request.uuid) error: $_"
        Update-RequestStatus -Id $Request.id -Status "failed" -Error $_.ToString()
        return $false
    }
}

function Check-RequestStatus {
    param([hashtable]$Request)
    try {
        $result = & certutil -config $CAConfig -view -restrict "RequestId=$($Request.requestId)" -out "Disposition" 2>&1 | Out-String
        if ($result -match "Request Disposition:") {
            if ($result -match "Issued") {
                Write-Log "Request $($Request.uuid) (CA ID: $($Request.requestId)) has been issued"
                # Retrieve the certificate
                $certFile = Join-Path $TempDir "$($Request.uuid).rsp"
                $retrieveResult = & certreq -retrieve -f -config $CAConfig $Request.requestId $certFile 2>&1 | Out-String
                if ($retrieveResult -match "Certificate retrieved" -and (Test-Path $certFile)) {
                    $b64Cert = [Convert]::ToBase64String([IO.File]::ReadAllBytes($certFile))
                    Remove-Item $certFile -Force -ErrorAction SilentlyContinue
                    Update-RequestStatus -Id $Request.id -Status "issued" -RequestId ([int]$Request.requestId) -B64Cert $b64Cert
                    Write-Log "Certificate retrieved and stored for $($Request.uuid)"
                }
                else {
                    Remove-Item $certFile -Force -ErrorAction SilentlyContinue
                    Write-Log "Failed to retrieve cert for $($Request.uuid): $retrieveResult"
                    Update-RequestStatus -Id $Request.id -Status "failed" -RequestId ([int]$Request.requestId) -Error "Issued but retrieval failed: $retrieveResult"
                }
            }
            elseif ($result -match "Denied") {
                Write-Log "Request $($Request.uuid) (CA ID: $($Request.requestId)) was denied"
                Update-RequestStatus -Id $Request.id -Status "denied" -RequestId ([int]$Request.requestId)
            }
            # If still pending, do nothing
        }
    }
    catch {
        Write-Log "Error checking status for $($Request.uuid): $_"
    }
}

# --- Main ---
Write-Log "CA Worker starting..."

# Step 1: Submit pending CSRs to CA
$pending = Get-PendingSubmissions
if ($pending.Count -gt 0) {
    Write-Log "Found $($pending.Count) pending submission(s)"
    foreach ($req in $pending) {
        Submit-CSR -Request $req
    }
}

# Step 2: Check status of submitted requests
$submitted = Get-SubmittedRequests
if ($submitted.Count -gt 0) {
    Write-Log "Checking $($submitted.Count) submitted request(s)"
    foreach ($req in $submitted) {
        Check-RequestStatus -Request $req
    }
}

Write-Log "CA Worker finished."
