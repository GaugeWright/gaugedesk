# Signs one Windows artifact with Azure Artifact Signing. Tauri invokes this
# per file through bundle.windows.signCommand, which runs before updater
# signatures are generated — the Authenticode signature therefore sits inside
# the payload the Tauri updater key signs, instead of invalidating it.
#
# Credentials come from the azure/login OIDC session on the runner. Every
# other credential source is excluded, exactly as Microsoft's own signing
# action excludes them: the module's default chain otherwise falls through to
# the interactive browser credential, which on a headless runner opens a
# browser and waits on a sign-in that never comes — that hang consumed a full
# 90-minute job timeout before this hook pinned the chain.
#
# Tauri reports a failing signCommand as nothing but `failed to run pwsh`, so
# every invocation appends a transcript to $RUNNER_TEMP/sign-windows-artifact.log
# and the workflow prints that file when the bundle step fails. The endpoint,
# account, and profile arrive as environment variables so this file carries
# no environment-specific values.
param(
  [Parameter(Mandatory = $true)][string]$Path
)
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'
$transcript = if ($env:RUNNER_TEMP) {
  Join-Path $env:RUNNER_TEMP 'sign-windows-artifact.log'
} else {
  Join-Path ([System.IO.Path]::GetTempPath()) 'sign-windows-artifact.log'
}
Start-Transcript -Path $transcript -Append | Out-Null
try {
  foreach ($name in @(
      'AZURE_ARTIFACT_SIGNING_ENDPOINT',
      'AZURE_ARTIFACT_SIGNING_ACCOUNT',
      'AZURE_ARTIFACT_SIGNING_CERTIFICATE_PROFILE')) {
    if (-not (Get-Item "env:$name" -ErrorAction SilentlyContinue).Value) {
      throw "missing required environment variable: $name"
    }
  }
  Invoke-ArtifactSigning `
    -Endpoint $env:AZURE_ARTIFACT_SIGNING_ENDPOINT `
    -CodeSigningAccountName $env:AZURE_ARTIFACT_SIGNING_ACCOUNT `
    -CertificateProfileName $env:AZURE_ARTIFACT_SIGNING_CERTIFICATE_PROFILE `
    -Files $Path `
    -FileDigest SHA256 `
    -TimestampRfc3161 'http://timestamp.acs.microsoft.com' `
    -TimestampDigest SHA256 `
    -ExcludeManagedIdentityCredential `
    -ExcludeWorkloadIdentityCredential `
    -ExcludeSharedTokenCacheCredential `
    -ExcludeVisualStudioCredential `
    -ExcludeVisualStudioCodeCredential `
    -ExcludeAzurePowerShellCredential `
    -ExcludeAzureDeveloperCliCredential `
    -ExcludeInteractiveBrowserCredential
} catch {
  Write-Error -ErrorRecord $_ -ErrorAction Continue
  Stop-Transcript | Out-Null
  exit 1
}
Stop-Transcript | Out-Null
