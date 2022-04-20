
# Set up WinRM

Set-Service -Name "WinRM" -StartupType Disabled
Stop-Service -Name "WinRM"

# Ensure PS-Remoting is enabled

if (-not (Get-PSSessionConfiguration) -or (-not (Get-ChildItem WSMan:\localhost\Listener))) {
    ## Use SkipNetworkProfileCheck to make available even on Windows Firewall public profiles
    ## Use Force to not be prompted if we're sure or not.
    Enable-PSRemoting -SkipNetworkProfileCheck -Force
}

# Allow WinRM over http

Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $false

# Allow WinRM unencrypted

Set-Item -Path WSMan:\localhost\Client\AllowUnencrypted -Value $false

# Delete user

$testUserAccountName = <'username'>
$testUserAccountPassword = (ConvertTo-SecureString -String <'password'> -AsPlainText -Force)
if (-not (Get-LocalUser -Name $testUserAccountName -ErrorAction Ignore)) {
    $newUserParams = @{
        Name                 = $testUserAccountName
        AccountNeverExpires  = $true
        PasswordNeverExpires = $true
        Password             = $testUserAccountPassword
    }
    $null = New-LocalUser @newUserParams
}

# Configure WinRM listener

## Find all HTTPS listners
$httpListeners = Get-ChildItem -Path WSMan:\localhost\Listener\ | where-object { $_.Keys -eq 'Transport=HTTP' }

## If not listeners are defined at all or no listener is configured to work with
## the server cert created, create a new one with a Subject of the computer's host name
## and bound to the server certificate.
if (-not $httpListeners) {
    $newWsmanParams = @{
        ResourceUri = 'winrm/config/Listener'
        SelectorSet = @{ Transport = "HTTP"; Address = "*" }
#        ValueSet    = @{ Hostname = $hostName; CertificateThumbprint = $serverCert.Thumbprint }
#        # UseSSL = $true
    }
    $null = New-WSManInstance @newWsmanParams
}

# Configure UAC

$newItemParams = @{
    Path         = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Name         = 'LocalAccountTokenFilterPolicy'
    Value        = 1
    PropertyType = 'DWORD'
    Force        = $true
}
$null = New-ItemProperty @newItemParams

# Allow traffic on Firewall

#region Ensure WinRM 5985 is open on the firewall

 $ruleDisplayName = 'Windows Remote Management (HTTP-In)'
 if (Remove-NetFirewallRule -DisplayName $ruleDisplayName -ErrorAction Ignore) {
         Remove-NetFirewallRule -Displayname $ruleDisplayName
     }
 }
 #endregion




