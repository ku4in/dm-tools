# Install Royal TS
wget https://download.royalapps.com/royalts/royaltsinstaller_7.02.50703.0_x64.msi -O royal.msi
msiexec /i royal.msi /qn, /quiet

$Desktop = [Environment]::GetFolderPath('Desktop')
cd $Desktop

# Install Royal PowerShell scripts
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module RoyalDocument.PowerShell -Force

Import-Module RoyalDocument.PowerShell
$store = New-RoyalStore -UserName "username"
$doc = New-RoyalDocument -Store $store -Name "Storage" -FileName "Clients.rtsz"
$dynfold = New-RoyalObject -folder $doc -Type RoyalDynamicFolder -Name "All clients"
$dynfold.ScriptInterpreter = "powershell"
$dynfold.ScriptContent = '$resp = Invoke-WebRequest "http://10.10.255.254/api/v1/royal/json"; Write-Output $resp.ToString()'
$o = Get-RoyalObject -Folder $doc -Name "Connections"
Remove-RoyalObject -Object $o -Force
$o = Get-RoyalObject -Folder $doc -Name "Credentials"
Remove-RoyalObject -Object $o -Force
$o = Get-RoyalObject -Folder $doc -Name "Tasks"
Remove-RoyalObject -Object $o -Force
Out-RoyalDocument -FileName "Clients.rtsz" -Document $doc
