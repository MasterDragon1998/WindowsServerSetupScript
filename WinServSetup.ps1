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

function Restart-Computer {
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
    Write-Host "Om deze actie te voltooien moet de server zometeen opnieuw opstarten" -ForeGroundColor Green
    Write-Host "Weet u zeker dat u de servernaam wilt veranderen? (y/n)?" -ForegroundColor Green
    $choice = Resolve-YesNo
    if($choice -eq $true){
        <# Naam moet worden aangepast #>
        Write-Host "Wat word de naam van de server?" -ForegroundColor Green
        $ServerName = Read-Host "Server naam"
        Rename-Computer -NewName $ServerName

        Restart-Computer
    }
}

function Update-NetworkSettings{
    Draw-Header
    $adapter = Get-NetAdapter | Select-Object Name, @{Name="IPAddress";Expression={(Get-NetIPAddress -InterfaceAlias $_.Name).IPAddress}}
    Write-Host "Name: $($adapter.Name) - $($adapter.IPAddress)"

    Write-Host ""
    Write-Host "Wil je netwerkinstellingen aanpassen? (y/n)" -ForegroundColor Green
    $choice = Resolve-YesNo
    if ($choice -eq $true) {
        # Netwerkinstellingen aanpassen
        $correctingevuld = $false
        while(!$correctingevuld){
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
            Draw-Header
            Write-Host "|                                 |"
            Write-Host "|      Controleer de gegevens     |"
            Write-Host "|                                 |"
            Write-Host "| Netwerk: $netwerknaam"
            Write-Host "| IP-adres: $IP"
            Write-Host "| Prefix: $prefixLength"
            Write-Host "| Default gateway: $gateway"
            Write-Host "|                                 |"
            Write-Host "| DNS 1: $dnsServer1"
            Write-Host "| DNS 2: $dnsServer2"
            Write-Host "|                                 |"
            Write-Host "+---------------------------------+"
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
    }
    Write-Host "Netwerkinstellingen zijn bijgewerkt" -ForegroundColor Green
    Write-Host "Druk op een knop om door te gaan..." -ForegroundColor Green
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
        Update-NetworkSettings
        Show-Menu
    }elseif($choice -eq "5"){
        Show-Menu
    }elseif($choice -eq "6"){
        Show-Menu
    }elseif($choice -eq "7"){
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