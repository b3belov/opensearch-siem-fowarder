param(
  [Parameter(Mandatory=$true)][string]$ForwarderHost,
  [Parameter(Mandatory=$true)][ValidateSet("windows-ad", "windows-sysmon")][string]$SourceId,
  [Parameter(Mandatory=$true)][string]$JsonPath,
  [Parameter(Mandatory=$true)][string]$Username,
  [Parameter(Mandatory=$true)][string]$Password,
  [Parameter(Mandatory=$true)][string]$ClientCertificatePath
)

$port = if ($SourceId -eq "windows-ad") { 8081 } else { 8082 }
$uri = "https://$ForwarderHost`:$port/"
$securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
$credential = [System.Management.Automation.PSCredential]::new($Username, $securePassword)
$certificate = Get-PfxCertificate -FilePath $ClientCertificatePath
$body = Get-Content -Raw -Path $JsonPath

Invoke-RestMethod `
  -Method Post `
  -Uri $uri `
  -Credential $credential `
  -Certificate $certificate `
  -ContentType "application/json" `
  -Body $body
