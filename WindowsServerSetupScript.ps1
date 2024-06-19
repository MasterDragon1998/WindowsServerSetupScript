<# Run as Admin #>
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process PowerShell -Verb RunAs "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
    exit;
}

Function Credits{
    Draw-Header
    Write-Host "|                                 |"
    Write-Host "|             Credits             |"
    Write-Host "|                                 |"
    Write-Host "|    Created by: Dennis Raangs    |"
    Write-Host "|                                 |"
    Write-Host "+---------------------------------+"
    Read-Host
}

Function Draw-Header{
    Clear-Host
    Write-Host "+---------------------------------+"
    Write-Host "|   Windows Server Setup Script   |"
    Write-Host "+---------------------------------+"
}

$activeservername = (gwmi win32_computersystem).name
$activedomainname = (gwmi win32_computersystem).domain
$activecurrenttime = Get-Date -Format "HH:mm:ss";

Function Update-Timezone{
    <# Tijdzone Instellen #>
    Write-Host -ForeGroundColor Green 'Tijdzone instellen...'
    Set-TimeZone -Name "W. Europe Standard Time"
    Write-Host -ForeGroundColor Green 'Tijdzone is ingesteld op W. Europe'
    Restart-Service w32time
    Write-Host "Druk een knop om door te gaan..."
    Read-Host
}

function Computer-Herstarten {
    <# Computer Herstarten #>
    # Create a RunOnce registry key to run the script after reboot
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    $scriptPath = $PSScriptRoot+"\WindowsServerSetupScript.ps1"
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
    Draw-Header
    Write-Host "De Server moet herstarten"

    <# Login Automatically#>
    Write-Host "Wil je automatisch weer inloggen? (y/n) (Werkt nog niet!)" -ForegroundColor Green
    $input = Read-Host
    if($input -eq "y"){
        $username = Read-Host "Gebruikersnaam"
        $password = Read-Host -Prompt 'Geef het Administrator wachtwoord op' -AsSecureString
        $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))
    
        # Set auto-logon settings to run once
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "AutoLogon" -Type String -Value "rundll32.exe user32.dll,LockWorkStation"

        # Set auto-logon settings
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Type String -Value "1"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUsername" -Type String -Value $username
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Type String -Value $password
    }

    Restart-Computer -Force
}

function Update-ServerName{
    <# Server naam instellen #>

    Draw-Header
    Write-Host "Weet u zeker dat u de servernaam wilt veranderen? (y/n)?" -ForegroundColor Green
    $input = Read-Host
    if($input -eq "y"){
        <# Naam moet worden aangepast #>
        Write-Host "Wat word de naam van de server?" -ForegroundColor Green
        $ServerName = Read-Host "Server naam"
        Rename-Computer -NewName $ServerName

        Computer-Herstarten
    }
}

function Update-NetworkSettings{
    Draw-Header
    $adapter = Get-NetAdapter | Select-Object Name, @{Name="IPAddress";Expression={(Get-NetIPAddress -InterfaceAlias $_.Name).IPAddress}}
    Write-Host "Name: $($adapter.Name) - $($adapter.IPAddress)"

    Write-Host ""
    Write-Host "Wil je netwerkinstellingen aanpassen? (y/n)" -ForegroundColor Green
    $input = Read-Host
    if ($input -eq "y") {
        # Netwerkinstellingen aanpassen
        $correctingevuld = $false
        while(!$correctingevuld){
            Write-Host "Wat word de naame van het netwerk?" -ForegroundColor Green
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
            $input = Read-Host
            if($input -eq "y"){ $correctingevuld = $true}
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

Function Update-Roles{
    $rollen = @("Active Directory Domain Services", "DNS Server", "DHCP Server")
    if($WinFeatureActiveDirectory){$rollen[0]="Active Directory Domain Services (Geinstalleerd)"}
    if($WinFeatureDNS){$rollen[1]="DNS Server (Geinstalleerd)"}
    if($WinFeatureDHCP){$rollen[2]="DHCP Server (Geinstalleerd)"}
    $gekozenrollen = @()
    $rollengekozen = $false

    while(!$rollengekozen){
        Draw-Header
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
}

function Create-Domain {
    Draw-Header
    if($WinFeatureActiveDirectory){$hasActiveDirectory=$true}

    Draw-Header
    Write-Host "Heeft u de server al een naam gegeven? (y/n)" -ForegroundColor Green
    $input = Read-Host
    if ($input -eq "n") {
        Write-Host "U moet uw server eerst een naam geven voordat het een domeincontroller kan worden"
        Write-Host "Druk een knop in om door te gaan..."
        Read-Host
        Update-ServerName
    }

    <# Controleerd of in deze sessie Active Directory al geinstalleerd is #>
    if(!$hasActiveDirectory){
        <# Rol installeren #>
        Write-Host "Active Directory word zometeen geinstalleerd, wilt u doorgaan met de installatie? (y/n)" -ForegroundColor Green
        $input = Read-Host
        if($input -eq "y"){
            $hasActiveDirectory = $true
        }
    }
    Draw-Header

    <# Domein promoten #>
    Write-Host "Moet er een nieuw domein aangemaakt worden? (y/n)" -ForegroundColor Green
    $input = Read-Host
    if($input -eq "y"){
        <# Nieuw Domein Aanmaken #>
        $gegevenskloppen = $false
        while(!$gegevenskloppen){
            Write-Host "Wat word de naam van het nieuwe domein? (geen .local toevoegen)" -ForegroundColor Green
            $domeinnaam = Read-Host
            $netbiosnaam = $domeinnaam
            $domeinnaam += ".local"
            Draw-Header
            Write-Host "|                                 |"
            Write-Host "|   Domein Naam : $domeinnaam     "
            Write-Host "|   NetBIOS Naam: $netbiosnaam    "
            Write-Host "+---------------------------------+"
            Write-Host ""
            Write-Host "kloppen de bovenstaande gegevens? (y/n)" -ForegroundColor Green
            $input = Read-Host
            if($input -eq "y"){
                $gegevenskloppen = $true
            }
        }
        if(!$WinFeatureActiveDirectory){
            Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
            Write-Host "Active Directory is geinstalleerd"
        }
        Write-Host "Domein Promoten"
        Install-ADDSForest -DomainName $domeinnaam -DomainNetBiosName $netbiosnaam -CreateDnsDelegation:$false -InstallDns:$true -NoRebootOnCompletion:$false -Force
        Computer-Herstarten
    }else{
        <# Domein Joinen #>
        Write-Host "Aan welk domein zou je de server toe willen voegen?" -ForegroundColor Green
        $domeinnaam = Read-Host
    }
    
}

function Setup-DHCP {
    Draw-Header

}

$WinFeatureActiveDirectory = $false
$WinFeatureDNS = $false
$WinFeatureDHCP = $false
Function Draw-Menu{
    $activecurrenttime = Get-Date -Format "HH:mm:ss";
    
    if((Get-WindowsFeature -Name AD-Domain-Services).InstallState -eq "Installed"){
        $WinFeatureActiveDirectory = $true
    }
    if((Get-WindowsFeature -Name DNS).InstallState -eq "Installed"){
        $WinFeatureDNS = $true
    }
    if((Get-WindowsFeature -Name DHCP).InstallState -eq "Installed"){
        $WinFeatureDHCP = $true
    }

    Draw-Header
    Write-Host "|                                 |"
    Write-Host "|       Systeem Informatie        |"
    Write-Host "|                                 |"
    Write-Host "| Server Name: $activeservername"
    Write-Host "| Domain Name: $activedomainname"
    Write-Host "| Script startup time: $activecurrenttime"
    Write-Host "|                                 |"
    Write-Host "| Active Directory: $WinFeatureActiveDirectory"
    Write-Host "| DNS: $WinFeatureDNS"
    Write-Host "| DHCP: $WinFeatureDHCP"
    Write-Host "|                                 |"
    Write-Host "+---------------------------------+"
    Write-Host "|                                 |"
    Write-Host "|              Menu               |"
    Write-Host "|                                 |"
    Write-Host "| 1. Tijdzone updaten             |"
    Write-Host "| 2. Servernaam aanpassen         |"
    Write-Host "| 3. Netwerk Instellen            |"
    Write-Host "| 4. Rollen Toevoegen             |"
    Write-Host "| 5. Domein Aanmaken              |"
    Write-Host "| 6. DHCP Configureren(Werkt nog nIet)"
    Write-Host "|                                 |"
    Write-Host "| 7. Credits                      |"
    Write-Host "|                                 |"
    Write-Host "|                           q=quit|"
    Write-Host "+---------------------------------+"

    $input = Read-Host "Select"
    if ($input -eq "1") {
        Update-Timezone
        Draw-Menu
    }elseif ($input -eq "2") {
        Update-ServerName
        Draw-Menu
    }elseif ($input -eq "3"){
        Update-NetworkSettings
        Draw-Menu
    }elseif ($input -eq "4"){
        Update-Roles
        Draw-Menu
    }elseif($input -eq "5"){
        Create-Domain
        Draw-Menu
    }elseif($input -eq "6"){
        Setup-DHCP
        Draw-Menu
    }elseif($input -eq "7"){
        Credits
        Draw-Menu
    }elseif($input -eq "q"){}else{
        Draw-Menu
    }
}

Draw-Menu