# Signs one Windows artifact with Azure Artifact Signing. Tauri invokes this
# per file through bundle.windows.signCommand, which runs before updater
# signatures are generated — the Authenticode signature therefore sits inside
# the payload the Tauri updater key signs, instead of invalidating it.
#
# Credentials come from the azure/login OIDC session on the runner; the
# TrustedSigning module's default credential chain picks up the Azure CLI
# login. The endpoint, account, and profile arrive as environment variables
# so this file carries no environment-specific values.
param(
  [Parameter(Mandatory = $true)][string]$Path
)
$ErrorActionPreference = 'Stop'
foreach ($name in @(
    'AZURE_ARTIFACT_SIGNING_ENDPOINT',
    'AZURE_ARTIFACT_SIGNING_ACCOUNT',
    'AZURE_ARTIFACT_SIGNING_CERTIFICATE_PROFILE')) {
  if (-not (Get-Item "env:$name" -ErrorAction SilentlyContinue).Value) {
    throw "missing required environment variable: $name"
  }
}
Invoke-TrustedSigning `
  -Endpoint $env:AZURE_ARTIFACT_SIGNING_ENDPOINT `
  -CodeSigningAccountName $env:AZURE_ARTIFACT_SIGNING_ACCOUNT `
  -CertificateProfileName $env:AZURE_ARTIFACT_SIGNING_CERTIFICATE_PROFILE `
  -Files $Path `
  -FileDigest SHA256 `
  -TimestampRfc3161 'http://timestamp.acs.microsoft.com' `
  -TimestampDigest SHA256
