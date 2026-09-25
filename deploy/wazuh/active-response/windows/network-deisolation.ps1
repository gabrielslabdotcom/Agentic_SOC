# Wazuh active response: remove host isolation installed by network-isolation.ps1.
# Restores the firewall profile defaults saved on first isolate.

$ErrorActionPreference = "Stop"

function Get-AgentRoot {
    return (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent)
}

function Write-ArLog([string]$Message) {
    $path = Join-Path (Get-AgentRoot) "active-response\active-responses.log"
    $line = "{0} network-deisolation: {1}" -f (Get-Date -Format "yyyy/MM/dd HH:mm:ss"), $Message
    Add-Content -LiteralPath $path -Value $line -ErrorAction SilentlyContinue
}

if ([Console]::IsInputRedirected) {
    try { $null = [Console]::In.ReadToEnd() } catch { }
}

$stateFile = Join-Path (Get-AgentRoot) "agentic-isolation.state"

# Restore the saved policy before deleting the allow rules so the manager session is not cut.
if (Test-Path -LiteralPath $stateFile) {
    $profiles = @(Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json)
    foreach ($profile in $profiles) {
        Set-NetFirewallProfile -Name $profile.Name -DefaultInboundAction $profile.DefaultInboundAction -DefaultOutboundAction $profile.DefaultOutboundAction
    }
    Remove-Item -LiteralPath $stateFile -Force
} else {
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow
}

Get-NetFirewallRule -DisplayName "AgenticSoc-ISO-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

Write-ArLog "de-isolated"
exit 0
