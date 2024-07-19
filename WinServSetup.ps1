<# Script als Administrator draaien #>
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}


<# Globale variabelen initializeren #>
$WinFeatureActiveDirectory = $false
$WinFeatureDHCP = $false
$WinFeatureDNS = $false
if((Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Installed"){
    $WinFeatureActiveDirectory = $true
}
if((Get-WindowsFeature -Name DNS).InstallState -eq "Installed"){
    $WinFeatureDNS = $true
}
if((Get-WindowsFeature -Name DHCP).InstallState -eq "Installed"){
    $WinFeatureDHCP = $true
}
$activeservername = (Get-WmiObject win32_computersystem).name
$activedomainname = (Get-WmiObject win32_computersystem).domain

<# Is script eerder uitgevoerd? #>
$settingspath = "C:\serversettings.json"
$eerderuitgevoerd = $false
if(Test-Path $settingspath){
    $eerderuitgevoerd = $true
}else{
    $eerderuitgevoerd = $false
}


<# Utility Functions #>
<# Debug #>
$debug = $true
Function Debug-Pause{
    if($debug){
        Write-Host "Debug pause" -ForegroundColor Magenta
        Write-Host "Press any key to continue" -ForegroundColor Magenta
        Read-Host
    }
}

<# Check voor correcte input (y/n) vragen #>
Function Resolve-YesNo{
    $inputcorrect = $false
    while(!$inputcorrect){
        $choice = Read-Host
        if($choice -eq "y"){
            return $true
        }elseif($choice -eq "n"){
            return $false
        }else{
            Write-Host "incorrecte invoer" -ForegroundColor Red
        }
    }
}

function Reset-Computer {
    <# Computer Herstarten #>
    # Create a RunOnce registry key to run the script after reboot
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    $scriptPath = $PSScriptRoot+"\WinServSetup.ps1"
    $scriptName = "MyScript"

    # Create the RunOnce key if it doesn't exist
    if (!(Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force
    }

    # Create the registry key
    New-ItemProperty -Path $registryPath -Name $scriptName -PropertyType String -Value "powershell -executionpolicy bypass -file $scriptPath"

    # Verify the registry key
    Get-ItemProperty -Path $registryPath -Name $scriptName

    # Restart the computer
    Show-Header
    Write-Host "De Server zal over enkele ogenblikken herstarten..." -ForegroundColor Green
    Start-Sleep(3)
    Restart-Computer -Force
}

<# Script Functions #>
Function Update-Timezone{
    Write-Host -ForeGroundColor Green 'Tijdzone instellen...'
    Set-TimeZone -Name "W. Europe Standard Time"
    Write-Host -ForeGroundColor Green 'Tijdzone is ingesteld op W. Europe'
    Restart-Service w32time
    Write-Host "Druk een knop om door te gaan..."
    Read-Host
}

function Update-ServerName{
    <# Server naam instellen #>
    Show-Header
    Write-Host "Om deze actie te voltooien moet de server zometeen opnieuw opstarten." -ForeGroundColor Green
    Write-Host "Weet u zeker dat u de servernaam wilt veranderen? (y/n)" -ForegroundColor Green
    $choice = Resolve-YesNo
    if($choice -eq $true){
        <# Naam moet worden aangepast #>
        Write-Host "Wat word de naam van de server?" -ForegroundColor Green
        $ServerName = Read-Host "Server naam"
        Rename-Computer -NewName $ServerName

        Reset-Computer
    }
}

function Update-NetworkSettings{
    $correctingevuld = $false
    while(!$correctingevuld){
        Show-Header
        $adapter = Get-NetAdapter | Select-Object Name, @{Name="IPAddress";Expression={(Get-NetIPAddress -InterfaceAlias $_.Name).IPAddress}}
        Write-Host "Name: $($adapter.Name) - $($adapter.IPAddress)"


        # Netwerkinstellingen aanpassen
        Write-Host "Wat word de naam van het netwerk?" -ForegroundColor Green
        $netwerknaam = Read-Host "Netwerk"
        Write-Host "Wat is het IP-adres van de server?" -ForegroundColor Green
        $IP = Read-Host "IP-adres"
        Write-Host "Wat is het prefixlength van dit netwerk?" -ForegroundColor Green
        $prefixLength = Read-Host "Prefix"
        Write-Host "Wat is de default gateway van de server?" -ForegroundColor Green
        $gateway = Read-Host "Default gateway"
        Write-Host "Welke dns server gebruik je?" -ForegroundColor Green
        $dnsServer1 = Read-Host "DNS 1"
        $dnsServer2 = Read-Host "DNS 2"

        <# Gebruiker Controlleerd gegevens #>
        Show-Header
        Write-Host "|                                                   |"
        Write-Host "|               Controleer de gegevens              |"
        Write-Host "|                                                   |"
        Write-Host "| Netwerk: $netwerknaam"
        Write-Host "| IP-adres: $IP"
        Write-Host "| Prefix: $prefixLength"
        Write-Host "| Default gateway: $gateway"
        Write-Host "|                                                   |"
        Write-Host "| DNS 1: $dnsServer1"
        Write-Host "| DNS 2: $dnsServer2"
        Write-Host "|                                                   |"
        Write-Host "+---------------------------------------------------+"
        Write-Host ""
        Write-Host "Is dit correct? (y/n)" -ForegroundColor Green
        $choice = Resolve-YesNo
        if($choice -eq $true){ $correctingevuld = $true}
    }


        <# Netwerk instellen #>
        $Null = Set-NetIPInterface -InterfaceAlias $($adapter.Name) -DHCP Disabled
        Remove-NetIPAddress -InterfaceAlias $($adapter.Name) -Confirm:$false
        Remove-NetRoute -InterfaceAlias $($adapter.Name) -DestinationPrefix "0.0.0.0/0" -Confirm:$false
        Rename-NetAdapter -Name $($adapter.Name) -NewName $netwerknaam
        # Set the IP address
        New-NetIPAddress -InterfaceAlias $netwerknaam -IPAddress $IP -PrefixLength $prefixLength -DefaultGateway $gateway
        Set-DnsClientServerAddress -InterfaceAlias $netwerknaam -ServerAddresses $dnsServer1, $dnsServer2


        Write-Host "Netwerkinstellingen zijn bijgewerkt" -ForegroundColor Green
        Write-Host "Druk op een knop om door te gaan..." -ForegroundColor Green
        Read-Host
}

Function Update-Roles{
    $rollen = @("Active Directory Domain Services", "DNS Server", "DHCP Server")
    if($WinFeatureActiveDirectory){$rollen[0]="Active Directory Domain Services (Geinstalleerd)"}
    if($WinFeatureDNS){$rollen[1]="DNS Server (Geinstalleerd)"}
    if($WinFeatureDHCP){$rollen[2]="DHCP Server (Geinstalleerd)"}
    $gekozenrollen = @()
    $rollengekozen = $false

    while(!$rollengekozen){
        Show-Header
        for ($i=0;$i -lt $rollen.Count; $i++){
            $isalgekozen = $false
            foreach($gekozenrol in $gekozenrollen){
                if($rollen[$i] -eq $gekozenrol){
                    <# Rol is al gekozen #>
                    $isalgekozen = $true
                }
            }
            if($isalgekozen){
                Write-Host "[X] $i : $($rollen[$i])"
            }else{
                Write-Host "[ ] $i : $($rollen[$i])"
            }
        }
        $i++
        Write-Host "    $i : Gekozen Opties Installeren!"

        $input = Read-Host "Select: "
        if($input){
            if($input -eq 4){
                <# Doorgaan #>
                $rollengekozen = $true
            }else{
                $isalgekozen = $false
                for ($i=0;$i -lt $gekozenrollen.Count; $i++){
                    if($rollen[$input] -eq $gekozenrollen[$i]){
                        <# Rol is al gekozen #>
                        $isalgekozen = $true
                        $gekozenrollen[$i] = $null
                    }
                }
                if(!$isalgekozen){
                    $gekozenrollen += $rollen[$input]
                }
            }
            
        }
        Write-Host "Gekozen rollen: $gekozenrollen"
    }


    $hasActiveDirectory
    # Add the selected roles
    foreach ($rol in $gekozenrollen) {
        switch ($rol) {
            "Active Directory Domain Services" {
                $hasActiveDirectory = $true
                Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
            }
            "DNS Server" {
                Add-WindowsFeature -Name DNS -IncludeManagementTools
            }
            "DHCP Server" {
                Add-WindowsFeature -Name DHCP -IncludeManagementTools
            }
            default {
                Write-Host "Unknown role: $rol"
            }
        }
    }

    if((Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Installed"){
        $WinFeatureActiveDirectory = $true
    }
    if((Get-WindowsFeature -Name DNS).InstallState -eq "Installed"){
        $WinFeatureDNS = $true
    }
    if((Get-WindowsFeature -Name DHCP).InstallState -eq "Installed"){
        $WinFeatureDHCP = $true
    }
}

function Install-Domain {
    Show-Header
    if($WinFeatureActiveDirectory){$hasActiveDirectory=$true}

    Show-Header
    Write-Host "Heeft u de server al een naam gegeven? (y/n)" -ForegroundColor Green
    $choice = Resolve-YesNo
    if ($choice -eq $false) {
        Write-Host "U moet uw server eerst een naam geven voordat het een domeincontroller kan worden" -ForegroundColor Green
        Write-Host "Druk een knop in om door te gaan..." -ForegroundColor Green
        Read-Host
        Update-ServerName
        return;
    }

    Write-Host "Is de tijdzone goed geconfigureerd? (y/n)" -ForegroundColor Green
    $choice = Resolve-YesNo
    if($input -eq $false){
        Update-Timezone
    }

    <# Controleerd of in deze sessie Active Directory al geinstalleerd is #>
    if(!$hasActiveDirectory){
        <# Rol installeren #>
        Write-Host "Active Directory word zometeen geinstalleerd, wilt u doorgaan met de installatie? (y/n)" -ForegroundColor Green
        $choice = Resolve-YesNo
        if($input -eq $true){
            $hasActiveDirectory = $true
        }
    }
    Show-Header

    <# Domein promoten #>
    Write-Host "Moet er een nieuw domein aangemaakt worden? (y/n)" -ForegroundColor Green
    $choice = Resolve-YesNo
    if($input -eq $true){ # <!---- Klopt iets niet
        <# Nieuw Domein Aanmaken #>
        $gegevenskloppen = $false
        while(!$gegevenskloppen){
            Write-Host "Wat word de naam van het nieuwe domein? (geen .local toevoegen)" -ForegroundColor Green
            $domeinnaam = Read-Host
            $netbiosnaam = $domeinnaam
            $domeinnaam += ".local"

            <# Safemodewachtwoord#>
            $wachtwoordcorrect = $false
            while(!$wachtwoordcorrect){
                Write-Host "Wat is je SafeModePassword? (minimaal 8 tekens)" -ForegroundColor Green 
                $safemodePassword = Read-Host "SafeModePassword" -AsSecureString
                Write-Host "Herhaal Safemode wachtwoord" -ForegroundColor green
                $safemodePassword2 = Read-Host "SafeModePassword" -AsSecureString

                $passwd1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($safemodePassword))
                $passwd2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($safemodePassword2))
                if($passwd1 -eq $passwd2){
                    <# Wachtwoord correct #>
                    $wachtwoordcorrect = $true
                }else{
                    <# Not equal #>
                    Write-Host "Wachtwoorden komen niet overeen, probeer opnieuw"
                }
            }

            Show-Header
            Write-Host "|                                                   |"
            Write-Host "|   Domein Naam : $domeinnaam     "
            Write-Host "|   NetBIOS Naam: $netbiosnaam    "
            Write-Host "|                                                   |"
            Write-Host "+---------------------------------------------------+"
            Write-Host ""
            Write-Host "kloppen de bovenstaande gegevens? (y/n)" -ForegroundColor Green
            $choice = Resolve-YesNo
            if($choice -eq $true){
                $gegevenskloppen = $true
            }
        }
        if(!$WinFeatureActiveDirectory){
            Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
            Write-Host "Active Directory is geinstalleerd"
        }
        Write-Host "Domein Promoten"
        Install-ADDSForest -DomainName $domeinnaam -DomainNetBiosName $netbiosnaam -CreateDnsDelegation:$false -InstallDns:$true -NoRebootOnCompletion:$false -Force -SafeModeAdministratorPassword $safemodePassword
        Read-Host
        Reset-Computer
    }else{
        <# Domein Joinen #>
        Write-Host "Aan welk domein zou je de server toe willen voegen?" -ForegroundColor Green
        $domeinnaam = Read-Host
    }
    
}

function Install-DHCP {
    $ipv4Address = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "127.0.0.1"}).IPAddress
    $adapter = Get-NetAdapter | Select-Object Name, @{Name="IPAddress";Expression={(Get-NetIPAddress -InterfaceAlias $_.Name).IPAddress}}
    Show-Header
    Write-Host "|                                                   |"
    Write-Host "|               DHCP Server Instellen               |"
    Write-Host "| Name: $($adapter.Name) - $($adapter.IPAddress)"
    Write-Host "|                                                   |"
    Write-Host "+---------------------------------------------------+"

    # Install DHCP server role
    $DHCPnoginstalleren = $false
    if((Get-WindowsFeature -Name DHCP).InstallState -eq "Installed"){}else{
        Write-Host "DHCP Rol is nog niet geinstalleerd en zal zometeen worden geinstalleerd." -ForegroundColor Green
        Write-Host "Wilt u doorgaan (y/n)" -ForegroundColor Green
        $choice = Resolve-YesNo
        if ($choice -eq $true) { $DHCPnoginstalleren = $true }else{ return; }
    }
    

    Write-Host "DHCP Server Instellen" -ForegroundColor Green
    $gegevenskloppen = $false
    while(!$gegevenskloppen){
        # Configure DHCP scope
        $scopeName = Read-Host "Enter the scope name"
        $startRange = Read-Host "Enter the start IP address of the scope"
        $endRange = Read-Host "Enter the end IP address of the scope"
        $subnetMask = Read-Host "Enter the subnet mask"
        $defaultGateway = Read-Host "Enter the default gateway"
        $dnsServer = Read-Host "Enter the DNS server"
        
        Show-Header

        Write-Host "|                                                   |"
        Write-Host "|               Controleer de gegevens              |"
        Write-Host "|                                                   |"
        Write-Host "|   Scopenaam: $scopeName"
        Write-Host "|   IP Range: $startRange - $endRange"
        Write-Host "|   Subnetmask: $subnetMask"
        Write-Host "|   Default Gateway: $defaultGateway"
        Write-Host "|   DNS Server: $dnsServer"
        Write-Host "|                                                   |"
        Write-Host "+---------------------------------------------------+"
        Write-Host "Kloppen de bovenstaande gegevens? (y/n)" -ForegroundColor Green
        $choice = Resolve-YesNo
        if ($choice -eq $true) { $gegevenskloppen = $true }
    }

    <# DHCP Rol installeren als nodig #>
    if($DHCPnoginstalleren -eq $true){
        Add-WindowsFeature -Name DHCP -IncludeManagementTools
        Write-Host "DHCP Rol geinstalleerd" -ForegroundColor Green
    }

    if((Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Installed"){
        # Authorize DHCP Server in AD
        Add-DhcpServerInDC -DnsName $activedomainname -IPAddress $ipv4Address
    }

    # Create security groups for DHCP Server Administration
    $securityGroups = "DHCP Administrators", "DHCP Users"
    foreach ($group in $securityGroups) {
        New-LocalGroup -Name $group -ErrorAction SilentlyContinue
    }

    <# DHCP Configureren #>
    Import-Module DhcpServer

    Add-DhcpServerv4Scope -Name $scopeName -StartRange $startRange -EndRange $endRange -SubnetMask $subnetMask
    Set-DhcpServerv4OptionValue -ScopeId 192.168.2.0 -OptionId 3 -Value $defaultGateway
    Set-DhcpServerv4OptionValue -ScopeId 192.168.2.0 -OptionId 6 -Value $dnsServer

    Write-Host "DHCP server setup complete" -ForegroundColor Green
    Write-Host "Druk een knop om door te gaan..." -ForegroundColor Green
    Read-Host
}

Function Setup-Wizard{
    <# Start Setup Wizard #>
}

Function Continue-Wizard{
    <# Wizard acties na reboot #>
}

<# Checken of settings al eerder waren opgeslagen #>
$powershellwizardvarspath = "C:\powershellwizard.json"
$settingsalreadymade = $false
if(Test-Path $powershellwizardvarspath){
    $jsonData = Get-Content -Path $settingspath -Raw
    $data = $jsonData | ConvertFrom-Json

    <#$ServerName = $data.ServerName
    $domeinnaam = $data.Domeinnaam
    $interfacenaam = $data.Interfacenaam
    $IP = $data.IP
    $prefixLength = $data.PrefixLength
    $gateway = $data.Gateway
    $dnsServer1 = $data.DNSServer1
    $dnsServer2 = $data.DNSServer2
    $moetDHCPinstalleren = $data.MoetDHCPinstalleren
    $moetNieuwdomeinaanmaken = $data.MoetNieuwdomeinaanmaken
    $safemodepassword = ConvertTo-SecureString -String $data.safemodepassword#>

    $settingsalreadymade = $true
}

<# Header #>
Function Show-Header{
    Clear-Host
    Write-Host "+---------------------------------------------------+"
    Write-Host "|                                                   |"
    Write-Host "|           Windows Server Setup Script             |"
    Write-Host "|                                                   |"
    Write-Host "+---------------------------------------------------+"
}

Function Show-Menu{
    if((Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Installed"){
        $WinFeatureActiveDirectory = $true
    }
    if((Get-WindowsFeature -Name DNS).InstallState -eq "Installed"){
        $WinFeatureDNS = $true
    }
    if((Get-WindowsFeature -Name DHCP).InstallState -eq "Installed"){
        $WinFeatureDHCP = $true
    }

    $activecurrenttime = Get-Date -Format "HH:mm:ss";

    Show-Header
    Write-Host "|                                                   |"
    Write-Host "|                Systeem Informatie                 |"
    Write-Host "|                                                   |"
    Write-Host "| Server Name: $activeservername"
    Write-Host "| Domain Name: $activedomainname"
    Write-Host "| Script startup time: $activecurrenttime"
    Write-Host "|                                                   |"
    Write-Host "| Active Directory: $WinFeatureActiveDirectory"
    Write-Host "| DNS: $WinFeatureDNS"
    Write-Host "| DHCP: $WinFeatureDHCP"
    Write-Host "|                                                   |"
    Write-Host "+---------------------------------------------------+"
    Write-Host "|                                                   |"
    Write-Host "|                       Menu                        |"
    Write-Host "|                                                   |"
    Write-Host "| 1. Setup Wizard                                   |"
    Write-Host "| 2. Tijdzone updaten                               |"
    Write-Host "| 3. Servernaam aanpassen                           |"
    Write-Host "| 4. Netwerk Instellen                              |"
    Write-Host "| 5. Rollen Toevoegen                               |"
    Write-Host "| 6. Domein Aanmaken                                |"
    Write-Host "| 7. DHCP Configureren                              |"
    Write-Host "|                                                   |"
    Write-Host "| 8. Credits                                        |"
    Write-Host "|                                                   |"
    Write-Host "|                                             q=quit|"
    Write-Host "+---------------------------------------------------+"

    $choice = Read-Host "Select"
    if ($choice -eq "1") {
        Setup-Wizard
        Show-Menu
    }elseif ($choice -eq "2") {
        Update-Timezone
        Show-Menu
    }elseif ($choice -eq "3"){
        Update-ServerName
        Show-Menu
    }elseif ($choice -eq "4"){
        Show-Header
        $adapter = Get-NetAdapter | Select-Object Name, @{Name="IPAddress";Expression={(Get-NetIPAddress -InterfaceAlias $_.Name).IPAddress}}
        Write-Host "Name: $($adapter.Name) - $($adapter.IPAddress)"
        Write-Host "Wil je netwerkinstellingen aanpassen? (y/n)" -ForegroundColor Green
        $choice = Resolve-YesNo
        if ($choice -eq $true) { Update-NetworkSettings }
        Show-Menu
    }elseif($choice -eq "5"){
        Update-Roles
        Show-Menu
    }elseif($choice -eq "6"){
        Install-Domain
        Show-Menu
    }elseif($choice -eq "7"){
        Show-Header
        $adapter = Get-NetAdapter | Select-Object Name, @{Name="IPAddress";Expression={(Get-NetIPAddress -InterfaceAlias $_.Name).IPAddress}}
        Write-Host "|                                                   |"
        Write-Host "|               Ethernet Instellingen               |"
        Write-Host "| Name: $($adapter.Name) - $($adapter.IPAddress)"
        Write-Host "|                                                   |"
        Write-Host "+---------------------------------------------------+"
        Write-Host "Heeft de server een statish IP adres? (y/n)" -ForegroundColor Green
        $choice = Resolve-YesNo
        if(!$choice -eq $true){
            <# Server heeft geen statisch IP adres #>
            Write-Host "Het word sterk aangeraden om een statish IP te gebruiken als DHCP Server!!" -ForegroundColor Green
            Write-Host "Druk een knop om door te gaan..." -ForegroundColor Green
            Read-Host
            Update-NetworkSettings
        }
        Install-DHCP
        Show-Menu
    }elseif($choice -eq "q"){}else{
        Show-Menu
    }
}

if(!$eerderuitgevoerd -eq $true){
    <# Eerste keer uitgevoerd #>
    Write-Host "Dit is de eerste keer dat het script op deze server word ingeladen" -ForegroundColor Green
    Write-Host "Wil je de setup wizard gebruiken? (y/n)" -ForegroundColor Green
    $choice = Resolve-YesNo
    if($choice -eq $true){
        <# Setup Wizard Gebruiken #>
        Setup-Wizard
    }

    $data = @{ eerderUitgevoerd = $true }
    $data | ConvertTo-Json | Out-File -FilePath $settingspath -Encoding UTF8
}

<# Menu #>
Show-Menu