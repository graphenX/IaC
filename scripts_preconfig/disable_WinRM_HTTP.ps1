
# Set up WinRM

Set-Service -Name "WinRM" -StartupType Disabled
Stop-Service -Name "WinRM"

# Ensure PS-Remoting is enabled

Disable-PSRemoting -SkipNetworkProfileCheck -Force

# Disallow WinRM over http

Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false

# Disallow WinRM unencrypted

Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $false






