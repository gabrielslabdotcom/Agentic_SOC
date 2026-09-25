# Wazuh active response: isolate this Windows host.
# Keeps loopback, the Wazuh manager, and RDP/SSH from ALLOWED_MGMT_IPS.
# Runs as SYSTEM via network-isolation.cmd. Manual API / HITL only.
# Config: C:\Program Files (x86)\ossec-agent\isolation.conf

$ErrorActionPreference = "Stop"

function Get-AgentRoot {
    return (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent)
}

function Write-ArLog([string]$Message) {
    $path = Join-Path (Get-AgentRoot) "active-response\active-responses.log"
    $dir = Split-Path $path -Parent
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $line = "{0} network-isolation: {1}" -f (Get-Date -Format "yyyy/MM/dd HH:mm:ss"), $Message
    Add-Content -LiteralPath $path -Value $line -ErrorAction SilentlyContinue
}

function Read-IsolationConfig {
    $root = Get-AgentRoot
    $candidates = @(
        (Join-Path $root "isolation.conf"),
        (Join-Path $PSScriptRoot "isolation.conf")
    )
    $path = $null
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            $path = $candidate
            break
        }
    }
    if (-not $path) {
        Write-ArLog "missing isolation.conf - refusing to change the firewall"
        exit 1
    }
    $map = @{}
    foreach ($raw in Get-Content -LiteralPath $path) {
        $line = $raw.Trim()
        if ($line -eq "" -or $line.StartsWith("#")) { continue }
        $idx = $line.IndexOf("=")
        if ($idx -lt 1) { continue }
        $key = $line.Substring(0, $idx).Trim()
        $val = $line.Substring($idx + 1).Trim()
        $map[$key] = $val
    }
    return $map
}

if ([Console]::IsInputRedirected) {
    try { $null = [Console]::In.ReadToEnd() } catch { }
}

$conf = Read-IsolationConfig
$manager = [string]$conf["WAZUH_MANAGER_IP"]
if ([string]::IsNullOrWhiteSpace($manager) -or $manager.StartsWith("<")) {
    Write-ArLog "WAZUH_MANAGER_IP is empty - refusing to change the firewall"
    exit 1
}
$sshPort = if ($conf["SSH_PORT"]) { $conf["SSH_PORT"] } else { "22" }
$rdpPort = if ($conf["RDP_PORT"]) { $conf["RDP_PORT"] } else { "3389" }
$mgmt = @()
if ($conf["ALLOWED_MGMT_IPS"]) {
    $mgmt = $conf["ALLOWED_MGMT_IPS"].Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith("<") }
}

$root = Get-AgentRoot
$stateFile = Join-Path $root "agentic-isolation.state"

if (-not (Test-Path -LiteralPath $stateFile)) {
    $saved = Get-NetFirewallProfile | Select-Object Name, DefaultInboundAction, DefaultOutboundAction
    $saved | ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding UTF8
}

Get-NetFirewallRule -DisplayName "AgenticSoc-ISO-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

# Allow rules go in before the default policy flips, so the manager session is not cut.
New-NetFirewallRule -DisplayName "AgenticSoc-ISO-Loopback-In" -Direction Inbound -Action Allow -RemoteAddress 127.0.0.1 -Profile Any | Out-Null
New-NetFirewallRule -DisplayName "AgenticSoc-ISO-Loopback-Out" -Direction Outbound -Action Allow -RemoteAddress 127.0.0.1 -Profile Any | Out-Null
New-NetFirewallRule -DisplayName "AgenticSoc-ISO-Manager-In" -Direction Inbound -Action Allow -Protocol Any -RemoteAddress $manager -Profile Any | Out-Null
New-NetFirewallRule -DisplayName "AgenticSoc-ISO-Manager-Out" -Direction Outbound -Action Allow -Protocol Any -RemoteAddress $manager -Profile Any | Out-Null

foreach ($ip in $mgmt) {
    $safe = ($ip -replace "[^0-9A-Za-z\.-]", "-")
    New-NetFirewallRule -DisplayName "AgenticSoc-ISO-RDP-$safe" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $rdpPort -RemoteAddress $ip -Profile Any | Out-Null
    New-NetFirewallRule -DisplayName "AgenticSoc-ISO-SSH-$safe" -Direction Inbound -Action Allow -Protocol TCP -LocalPort $sshPort -RemoteAddress $ip -Profile Any | Out-Null
}

Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Block

Write-ArLog "isolated (manager $manager)"
exit 0
