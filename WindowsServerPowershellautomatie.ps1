<# Debug #>
$debug = $true
Function Debug-Pause{
    if($debug){
        Write-Host "Debug pause" -ForegroundColor Magenta
        Write-Host "Press any key to continue" -ForegroundColor Magenta
        Read-Host
    }
}

<# Script als Administrator draaien #>
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

<# Header #>
Function Draw-Header{
    Clear-Host
    Write-Host "+---------------------------------------------------+"
    Write-Host "|                                                   |"
    Write-Host "|           Windows Server Setup Script             |"
    Write-Host "|                                                   |"
    Write-Host "+---------------------------------------------------+"
}

$settingspath = "C:\ServerSettings.json"
$settingsalreadymade = $false
if(Test-Path $settingspath){
    $jsonData = Get-Content -Path $settingspath -Raw
    $data = $jsonData | ConvertFrom-Json

    $ServerName = $data.ServerName
    $domeinnaam = $data.Domeinnaam
    $interfacenaam = $data.Interfacenaam
    $IP = $data.IP
    $prefixLength = $data.PrefixLength
    $gateway = $data.Gateway
    $dnsServer1 = $data.DNSServer1
    $dnsServer2 = $data.DNSServer2
    $moetDHCPinstalleren = $data.MoetDHCPinstalleren
    $moetNieuwdomeinaanmaken = $data.MoetNieuwdomeinaanmaken
    $safemodepassword = ConvertTo-SecureString -String $data.safemodepassword

    $settingsalreadymade = $true
}

if(!$settingsalreadymade){
    <# Gegevens moeten nog worden ingesteld #>
    <# Autologin wachtwoord opvragen #>
    # $adminPassword = Read-Host -Prompt 'Geef het Administrator wachtwoord op: [Pa$$w0rd]'  -AsSecureString 

    <# Gegevens opvragen #>
    $gegevenskloppen = $false
    while(!$gegevenskloppen){
        Draw-Header
        <# Gegevens opvragen #>
        <# Naam moet worden aangepast #>
        Write-Host "Wat word de naam van de server?" -ForegroundColor Green
        $ServerName = Read-Host "Server naam"
        Write-Host "Moet er een nieuw domein aangemaakt worden? (y/n)" -ForegroundColor Green
        $moetNieuwdomeinaanmaken = Read-Host
        if($moetNieuwdomeinaanmaken -eq "y"){
            $moetNieuwdomeinaanmaken = $true
            Write-Host "Wat word de naam van het nieuwe domein? (geen .local toevoegen)" -ForegroundColor Green
            $domeinnaam = Read-Host
            $netbiosnaam = $domeinnaam
            $domeinnaam += ".local"
            <# Safemodepassword #>
            Write-Host "Wat word de safemodepassword?" -ForegroundColor Green 
            $safemodepassword = Read-Host -AsSecureString
            $safemodepassword = ConvertFrom-SecureString -SecureString $safemodepassword
            <# Forest level? #>
        }else{
            $moetNieuwdomeinaanmaken = $false
            Write-Host "Aan welk domein moet de server toegevoegd worden?" -ForegroundColor Green
            $domeinnaam = Read-Host
        }
        <# ip configuratie #>
        Write-Host "Wil je de ethernet instellingen aanpassen? (y/n)" -ForegroundColor Green
        $input = Read-Host
        if($input -eq "y"){
            $ethernetconfiguratieaanpassen = $true

            $adapter = Get-NetAdapter | Select-Object Name, @{Name="IPAddress";Expression={(Get-NetIPAddress -InterfaceAlias $_.Name).IPAddress}}
            Write-Host "Name: $($adapter.Name) - $($adapter.IPAddress)"


            Write-Host "Welke naam wil je je ethernet interface geven?" -ForegroundColor Green
            $interfacenaam = Read-Host
            Write-Host "Wat is het IP-adres van de server?" -ForegroundColor Green
            $IP = Read-Host "IP-adres"
            Write-Host "Wat is het prefixlength van dit netwerk?" -ForegroundColor Green
            $prefixLength = Read-Host "Prefix"
            Write-Host "Wat is de default gateway van de server?" -ForegroundColor Green
            $gateway = Read-Host "Default gateway"
            Write-Host "Welke dns server gebruik je?" -ForegroundColor Green
            $dnsServer1 = Read-Host "DNS 1"
            $dnsServer2 = Read-Host "DNS 2"
        }else{$ethernetconfiguratieaanpassen = $false}
        <# DHCP #>
        Write-Host "Wilt u een DHCP Server installeren en configureren? (y/n) " -ForegroundColor Green
        $moetDHCPinstalleren = Read-Host
        <# DHCP Configs etc. #>
        if($moetDHCPinstalleren -eq "y"){
            $moetDHCPinstalleren = $true
        }else{$moetDHCPinstalleren = $false}

        <#config check #>
        Draw-Header
        Write-Host "|                                                   |"
        Write-Host "|               Ingevoerde Gegevens                 |"
        Write-Host "|                                                   |"
        Write-Host "|  Servernaam: $ServerName"
        Write-Host "|                                                   |"
        if($moetNieuwdomeinaanmaken -eq $true){
        Write-Host "|               Nieuw domein aanmaken               |"
        Write-Host "|  Nieuw domein naam: $domeinnaam"
        }else{
        Write-Host "|               Aan bestaand domein toevoegen       |"
        Write-Host "|  Bestaande domein naam: $domeinnaam"
        }
        if($ethernetconfiguratieaanpassen){
            Write-Host "|                                                   |"
            Write-Host "|                                                   |"
            Write-Host "|               Ethernet configuratie"
            Write-Host "|                                                   |"
            Write-Host "|  Interfacenaam: $interfacenaam"
            Write-Host "|  IP Address: $IP/$prefixlength"
            Write-Host "|  Gateway: $gateway"
            Write-Host "|  DNS 1: $dnsServer1"
            Write-Host "|  DNS 2: $dnsServer2"
            Write-Host "|                                                   |"
        }
        if($moetDHCPinstalleren -eq "y"){
        Write-Host "|               DHCP Installeren: Ja                |"
        }
        Write-Host "|                                                   |"
        Write-Host "+---------------------------------------------------+"
        Write-Host ""
        Write-Host "Kloppen deze gegevens? (y/n)" -ForegroundColor Green
        $input = Read-Host
        if($input -eq "y"){
            $gegevenskloppen = $true
        }
    }

    <# Data to JSON #>
    Write-Host "Gegevens wegschrijven naar bestand: $settingspath" -ForegroundColor Green
    $data = @{
        ServerName = $ServerName
        Domeinnaam = $domeinnaam
        Interfacenaam = $interfacenaam
        IP = $IP
        PrefixLength = $prefixLength
        Gateway = $gateway
        DNSServer1 = $dnsServer1
        DNSServer2 = $dnsServer2
        MoetDHCPinstalleren = $moetDHCPinstalleren
        MoetNieuwdomeinaanmaken = $moetNieuwdomeinaanmaken
        safemodepassword = $safemodepassword
        ethernetconfiguratieaanpassen = $ethernetconfiguratieaanpassen
    }
    $data | ConvertTo-Json | Out-File -FilePath "C:\ServerSettings.json" -Encoding UTF8
    Write-Host "Gegevens weggeschreven naar bestand: $settingspath" -ForegroundColor Green


    <# Acties uitvoeren #>
    <# systemvars ophalen #>
    $adapter = Get-NetAdapter | Select-Object Name, @{Name="IPAddress";Expression={(Get-NetIPAddress -InterfaceAlias $_.Name).IPAddress}}
    <# Tijdzone Instellen #>
    Write-Host -ForeGroundColor Green 'Tijdzone instellen...'
    Set-TimeZone -Name "W. Europe Standard Time"
    Write-Host -ForeGroundColor Green 'Tijdzone is ingesteld op W. Europe'
    Restart-Service w32time
    <# ethernet interfaces configureren #>
    if($ethernetconfiguratieaanpassen -eq $true){
        Write-Host "Name: $($adapter.Name) - $($adapter.IPAddress)"
        Rename-NetAdapter -Name $($adapter.Name) -NewName $interfacenaam
        New-NetIPAddress -InterfaceAlias $interfacenaam -IPAddress $IP -PrefixLength $prefixLength -DefaultGateway $gateway
        Set-DnsClientServerAddress -InterfaceAlias $interfacenaam -ServerAddresses $dnsServer1, $dnsServer2
        Write-Host "Ethernet Geconfigureerd" -ForegroundColor Green
    }
    <# Nieuw domein aanmaken? #>
    if((Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Installed"){}else{
        Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    }
    if((Get-WindowsFeature -Name DNS).InstallState -eq "Installed"){}else{
        Add-WindowsFeature -Name DNS -IncludeManagementTools
    }
    if($moetDHCPinstalleren -eq $true){
        if((Get-WindowsFeature -Name DHCP).InstallState -eq "Installed"){}else{
            Add-WindowsFeature -Name DHCP -IncludeManagementTools
        }
    }


    <# Computer Herstarten #>
    <# Autologin #>
    $RegistryLocation = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty $RegistryLocation -Name 'AutoAdminLogon' -Value '1'  
    Set-ItemProperty $RegistryLocation -Name 'DefaultUsername' -Value 'administrator'
    Set-ItemProperty $RegistryLocation -Name 'DefaultPassword' -Value $password
    # Create a RunOnce registry key to run the script after reboot
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    $scriptPath = $PSScriptRoot+"\WindowsServerPowershellautomatie.ps1"
    $scriptName = "MyScript"

    # Create the RunOnce key if it doesn't exist
    if (!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force
    }

    # Create the registry key
    New-ItemProperty -Path $registryPath -Name $scriptName -PropertyType String -Value "powershell -executionpolicy bypass -file $scriptPath"

    # Verify the registry key
    Get-ItemProperty -Path $registryPath -Name $scriptName

    Write-Host "De computer zal zo herstarten..." -ForegroundColor Green
    Start-Sleep(3)
    Debug-Pause
    <# Computer hernoemen #>
    Rename-Computer -NewName $ServerName -LocalCredential Administrator -Restart
}else{
    <# Settings bestaan al #>
    Draw-Header
    <# Domein Promoten #>
    if($moetNieuwdomeinaanmaken -eq $true){
        <# Nieuw Domein Aanmaken #>
        Write-Host "Domein Promoten"
        Install-ADDSForest -DomainName $domeinnaam -DomainNetBiosName $netbiosnaam -CreateDnsDelegation:$false -InstallDns:$true -NoRebootOnCompletion:$false -SafeModeAdministratorPassword:$safemodepassword -Force
    }else{
        <# Domein Joinen #>
        <# Var $domeinnaam bestaat al!!! #>
    }
    Write-Host "De server is geconfigureerd." -ForegroundColor Green
    Write-Host "De computer zal zo herstarten..." -ForegroundColor Green
    Start-Sleep(3)
    Debug-Pause
    Restart-Computer -Force
}