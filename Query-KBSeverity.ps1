$Global:TargetKBs = @("KB5041585", "KB5040442", "KB5039212")
$Global:QueryAllUniqueKBs = $true

$Global:ForceUpdate = $false
$Global:ShowCachedResults = $false
$Global:CacheFilePath = "C:\temp\SecurityUpdateCache.json"
$Global:UniqueKBFilePath = "C:\temp\UniqueKBs.txt"

Clear-Host
Write-Host "MSRC Severity Results:"

if (-not (Test-Path $Global:CacheFilePath)) {
    $Global:ForceUpdate = $true
} else {
    $Global:ForceUpdate = $false
}

function Query-KBSeverity {
    try {
        if (-not $Global:ForceUpdate -and (Test-Path $Global:CacheFilePath)) {
            $reportData = Get-Content -Path $Global:CacheFilePath | ConvertFrom-Json
            if ($Global:ShowCachedResults) {
                $reportData | Out-GridView
                return
            }
        } else {
            if (-not (Get-Module MSRCSecurityUpdates)) {
                Install-Module MSRCSecurityUpdates -Force
            }
            $ReportingMonth = (Get-Date).ToString("yyyy-MMM")
            $reportData = Get-MsrcCvrfDocument -ID $ReportingMonth | Get-MsrcCvrfAffectedSoftware
            $reportData | ConvertTo-Json | Set-Content -Path $Global:CacheFilePath
        }

        if ($Global:ForceUpdate) {
            Extract-UniqueKBs $reportData
        }

        if ($Global:QueryAllUniqueKBs -and (Test-Path $Global:UniqueKBFilePath)) {
            $Global:TargetKBs = Get-Content -Path $Global:UniqueKBFilePath
        }

        $criticalKBs = @()
        $importantKBs = @()
        $moderateKBs = @()
        $lowKBs = @()

        foreach ($kb in $Global:TargetKBs) {
            $filteredResult = $reportData | Where-Object { $_.KBArticle -match $kb }

            $hasCritical = $filteredResult | Where-Object { $_.Severity -eq "Critical" }
            $hasImportant = $filteredResult | Where-Object { $_.Severity -eq "Important" }
            $hasModerate = $filteredResult | Where-Object { $_.Severity -eq "Moderate" }
            $hasLow = $filteredResult | Where-Object { $_.Severity -eq "Low" }

            if ($hasCritical) {
                $criticalKBs += "${kb}: Critical"
            } elseif ($hasImportant) {
                $importantKBs += "${kb}: Important"
            } elseif ($hasModerate) {
                $moderateKBs += "${kb}: Moderate"
            } elseif ($hasLow) {
                $lowKBs += "${kb}: Low"
            }
        }

        $criticalKBs | ForEach-Object { Write-Host $_ -ForegroundColor Red }
        $importantKBs | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
        $moderateKBs | ForEach-Object { Write-Host $_ -ForegroundColor DarkYellow }
        $lowKBs | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
    } catch {
        Throw "Error retrieving security updates: $($_.Exception.Message)"
    }
}

function Extract-UniqueKBs {
    param (
        [Parameter(Mandatory=$true)]
        $reportData
    )

    $content = $reportData | ConvertTo-Json -Compress
    $matches = [regex]::Matches($content, '\bKB\d+\b')
    $uniqueKBs = $matches | ForEach-Object { $_.Value } | Sort-Object -Unique
    $uniqueKBs | Out-File -FilePath $Global:UniqueKBFilePath
}

Query-KBSeverity
