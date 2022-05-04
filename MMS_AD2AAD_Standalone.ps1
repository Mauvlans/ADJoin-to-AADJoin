# ***************************************************************************
#
# Purpose: Script to Migrate AD join to Azure AD Join
#
# ------------- DISCLAIMER -------------------------------------------------
# This script code is provided as is with no guarantee or waranty concerning
# the usability or impact on systems and may be used, distributed, and
# modified in any way provided the parties agree and acknowledge the 
# Microsoft or Microsoft Partners have neither accountabilty or 
# responsibility for results produced by use of this script.
#
# Microsoft will not provide any support through any means.
# ------------- DISCLAIMER -------------------------------------------------
#
# ***************************************************************************

#prep Files
#net localgroup administrators /add "AzureAD\UserUpn"

#Start Transcription
Write-Output "Writing Local Files" 
$path = $(Join-Path $env:ProgramData CustomScripts)
if (!(Test-Path $path)) {
    New-Item -Path $path -ItemType Directory -Force -Confirm:$false
}
Start-Transcript -Path C:\ProgramData\CustomScripts\AD2AADJ.txt -NoClobber

# Script varibles
$DomainAdmin = "DOMAIN\USERNAME"
$DomainAdminPassword = "PASSWORD"
$TempUserPassword = "P@ssword!"
$TempUser = "MMSTemp"

function Add-Scripts {
    
# Post Reboot Script
$content = @'
Start-Transcript -Path C:\ProgramData\CustomScripts\AD2AADJ-R1.txt -NoClobber
Write-Output "Writing Run Once for Post Reboot 2" 
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"

set-itemproperty $RunOnceKey "NextRun" ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File ' + "C:\ProgramData\CustomScripts\PostRunOnce2.ps1")

# Install Provisioning PPKG
Install-ProvisioningPackage -PackagePath "C:\ProgramData\CustomScripts\AAD Join.ppkg" -ForceInstall -QuietInstall

Stop-Transcript
restart-computer

'@
 
# Creates PS1 and dumps to ProgramData\CustomScripts
Write-Output "Writing Local Files" 
$path = $(Join-Path $env:ProgramData CustomScripts)
if (!(Test-Path $path)) {
    New-Item -Path $path -ItemType Directory -Force -Confirm:$false
}
Out-File -FilePath $(Join-Path $env:ProgramData CustomScripts\PostRunOnce.ps1) -Encoding unicode -Force -InputObject $content -Confirm:$false

##############################################################################################################################################

# 2nd Post Reboot Script
$content = @'
Start-Transcript -Path C:\ProgramData\CustomScripts\AD2AADJ-R2.txt -NoClobber
Write-Output "Writing Run Once for Post Reboot " 
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"

set-itemproperty $RunOnceKey "NextRun" ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File ' + "C:\ProgramData\CustomScripts\PostRunOnce3.ps1")

Write-Output "Escrow current Numeric Key" 
function Test-Bitlocker ($BitlockerDrive) {
    #Tests the drive for existing Bitlocker keyprotectors
    try {
        Get-BitLockerVolume -MountPoint $BitlockerDrive -ErrorAction Stop
    } catch {
        Write-Output "Bitlocker was not found protecting the $BitlockerDrive drive. Terminating script!"
    }
}
function Get-KeyProtectorId ($BitlockerDrive) {
    #fetches the key protector ID of the drive
    $BitLockerVolume = Get-BitLockerVolume -MountPoint $BitlockerDrive
    $KeyProtector = $BitLockerVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
    return $KeyProtector.KeyProtectorId
}
function Invoke-BitlockerEscrow ($BitlockerDrive,$BitlockerKey) {
    #Escrow the key into Azure AD
    try {
        BackupToAAD-BitLockerKeyProtector -MountPoint $BitlockerDrive -KeyProtectorId $BitlockerKey -ErrorAction SilentlyContinue
        Write-Output "Attempted to escrow key in Azure AD - Please verify manually!"
    } catch {
        Write-Error "Debug"
    }
}
#endregion functions
#region execute
$BitlockerVolumers = Get-BitLockerVolume
$BitlockerVolumers |
ForEach-Object {
$MountPoint = $_.MountPoint
$RecoveryKey = [string]($_.KeyProtector).RecoveryPassword
if ($RecoveryKey.Length -gt 5) {
    $DriveLetter = $MountPoint
    Write-Output $DriveLetter
    Test-Bitlocker -BitlockerDrive $DriveLetter
    $KeyProtectorId = Get-KeyProtectorId -BitlockerDrive $DriveLetter
    Invoke-BitlockerEscrow -BitlockerDrive $DriveLetter -BitlockerKey $KeyProtectorId
}
}

# Remove AutoLogin
Write-Output "Remove user Auto Login"
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty $RegPath "AutoAdminLogon" -Value "0" -type String 
Stop-Transcript
restart-computer
'@
 
# Creates PS1 and dumps to ProgramData\CustomScripts
Write-Output "Writing Local Files" 
$path = $(Join-Path $env:ProgramData CustomScripts)
if (!(Test-Path $path)) {
    New-Item -Path $path -ItemType Directory -Force -Confirm:$false
}
Out-File -FilePath $(Join-Path $env:ProgramData CustomScripts\PostRunOnce2.ps1) -Encoding unicode -Force -InputObject $content -Confirm:$false

##############################################################################################################################################

# Post Reboot Script 3
$content = @'
Start-Transcript -Path C:\ProgramData\CustomScripts\AD2AADJ-R3.txt -NoClobber
$FileName = "C:\ProgramData\CustomScripts\AAD Join.ppkg"
if (Test-Path $FileName) {
  Remove-Item $FileName
}

Remove-LocalUser -name MMSTemp

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty $RegPath "AutoAdminLogon" -Value "0" -type String
Set-ItemProperty $RegPath "DefaultUsername" -Value "null" -type String 
Set-ItemProperty $RegPath "DefaultPassword" -Value "null" -type String

Start-Process -FilePath "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe"
Stop-Transcript
'@
 
# Creates PS1 and dumps to ProgramData\CustomScripts
Write-Output "Writing Local Files" 
$path = $(Join-Path $env:ProgramData CustomScripts)
if (!(Test-Path $path)) {
    New-Item -Path $path -ItemType Directory -Force -Confirm:$false
}
Out-File -FilePath $(Join-Path $env:ProgramData CustomScripts\PostRunOnce3.ps1) -Encoding unicode -Force -InputObject $content -Confirm:$false

##############################################################################################################################################

# User File Copy Script
$content = @'
Start-Transcript -Path C:\ProgramData\CustomScripts\AD2AADJ-UserCopy.txt -NoClobber
# ***************************************************************************
#
# Purpose: Script to copy folder to user profile
#
# ------------- DISCLAIMER -------------------------------------------------
# This script code is provided as is with no guarantee or waranty concerning
# the usability or impact on systems and may be used, distributed, and
# modified in any way provided the parties agree and acknowledge the 
# Microsoft or Microsoft Partners have neither accountabilty or 
# responsibility for results produced by use of this script.
#
# Microsoft will not provide any support through any means.
# ------------- DISCLAIMER -------------------------------------------------
#
# Robocopy Logic derived from https://newbedev.com/custom-robocopy-progress-bar-in-powershell
#
# Set-Owner Logic derived from https://learn-powershell.net/2014/06/24/changing-ownership-of-file-or-folder-using-powershell/
#
# Get-Folder Logic derived from https://stackoverflow.com/questions/25690038/how-do-i-properly-use-the-folderbrowserdialog-in-powershell
#
# ***************************************************************************

Function Get-Folder($initialDirectory="c:\Users\"){
    [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")|Out-Null

    $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
    $foldername.Description = "Select a folder"
    $foldername.rootfolder = "MyComputer"
    $foldername.SelectedPath = $initialDirectory

    if($foldername.ShowDialog() -eq "OK")
    {
        $folder += $foldername.SelectedPath
    }
    return $folder
}

function Set-Owner {
    # Define the owner account/group
$Account = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList 'BUILTIN\Administrators';

# Get a list of folders and files
$ItemList = Get-ChildItem -Path $ProfileFolder -Recurse;

# Iterate over files/folders
foreach ($Item in $ItemList) {
    $Acl = $null; # Reset the $Acl variable to $null
    $Acl = Get-Acl -Path $Item.FullName; # Get the ACL from the item
    $Acl.SetOwner($Account); # Update the in-memory ACL
    Set-Acl -Path $Item.FullName -AclObject $Acl;  # Set the updated ACL on the target item
}
}

function Copy-Folder {

Set-Location "C:\Windows\System32"

.\Robocopy.exe $ProfileFolder $Destination /E /XC /XN /XO /r:0 /XD "$ProfileFolder\Appdata"

#.\robocopy $ProfileFolder $Destination /NDL /NJH /NJS /E /XC /XN /XO /r:0 /XD "$ProfileFolder\Appdata" | ForEach-Object{$data = $_.Split([char]9); if("$($data[4])" -ne "") { $file = "$($data[4])"} ;Write-Progress "Percentage $($data[0])" -Activity "Robocopy" -CurrentOperation "$($file)"  -ErrorAction SilentlyContinue; }

}


$ProfileFolder = Get-Folder
$Destination = $env:USERPROFILE

Set-Owner

Copy-Folder
Stop-Transcript
'@
 
# Creates PS1 and dumps to ProgramData\CustomScripts
Write-Output "Writing Local Files" 
$path = $(Join-Path $env:ProgramData CustomScripts)
if (!(Test-Path $path)) {
    New-Item -Path $path -ItemType Directory -Force -Confirm:$false
}
Out-File -FilePath $(Join-Path $env:ProgramData CustomScripts\Copy-Userprofile.ps1) -Encoding unicode -Force -InputObject $content -Confirm:$false

}

function Move-PPKG {

#Copy PPKG to Localfolder
$path = $(Join-Path $env:ProgramData CustomScripts)
if (!(Test-Path $path)) {
    New-Item -Path $path -ItemType Directory -Force -Confirm:$false
}
#Copy-Item -Path ".\AAD Join.ppkg" -Destination "C:\ProgramData\CustomScripts\AAD Join.ppkg"
Copy-Item -Path "$PSScriptRoot\AAD Join.ppkg" -Destination "C:\ProgramData\CustomScripts\AAD Join.ppkg"

}

function Add-LocalUser {
  
    # Create Local Account 
    Write-Output "Creating Local User Account"
    $Password = ConvertTo-SecureString -AsPlainText $TempUserPassword -force
    New-LocalUser -Name $TempUser -Password $Password -Description "account for autologin" -AccountNeverExpires
    Add-LocalGroupMember -Group "Administrators" -Member $TempUser
    
}

function Set-Autologin {

# Set Auto login Regestry
Write-Output "Setting user account to Auto Login" 
$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty $RegPath "AutoAdminLogon" -Value "1" -type String -Verbose
Set-ItemProperty $RegPath "DefaultUsername" -Value $TempUser -type String -Verbose
Set-ItemProperty $RegPath "DefaultPassword" -Value $TempUserPassword -type String -Verbose

}

function Disable-OOBEPrivacy  {

# Set variables to indicate value and key to set
$RegistryPath = 'HKCU:\Software\Policies\Microsoft\Windows\OOBE'
$Name = 'DisablePrivacyExperience'
$Value = '1'
# Create the key if it does not exist
If (-NOT (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
}  
# Now set the value
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force -Verbose

# Set variables to indicate value and key to set
$RegistryPath = 'HKLM:\Software\Policies\Microsoft\Windows\OOBE'
$Name = 'DisablePrivacyExperience'
$Value = '1'
# Create the key if it does not exist
If (-NOT (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
}  
# Now set the value
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force -Verbose
}

function Set-RunOnce {
    
# Set Run Once Regestry
Write-Host "Changing RunOnce script." 

$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"

set-itemproperty $RunOnceKey "NextRun" ('C:\Windows\System32\WindowsPowerShell\v1.0\Powershell.exe -executionPolicy Unrestricted -File ' + "C:\ProgramData\CustomScripts\PostRunOnce.ps1") -Verbose
}

function Set-Bitlocker {
  
    Suspend-BitLocker -MountPoint "C:" -RebootCount 3 -Verbose

}

function Remove-Hybrid {

#Remove machine from Hybrid Join
.\C:\Windows\System32\dsregcmd.exe /leave
    
}

function Remove-ADJoin {

# Remove Machines from AD
Write-Verbose "Removing computer from domain and forcing restart"
$pw = $DomainAdminPassword | ConvertTo-SecureString -asPlainText -Force
$usr = $DomainAdmin
$pc = "localhost"
$creds = New-Object System.Management.Automation.PSCredential($usr, $pw)
Stop-Transcript
Remove-Computer -ComputerName $pc -Credential $creds -Verbose -Restart -Force

}


# Main Logic

Add-Scripts

Move-PPKG

Add-LocalUser

Set-Autologin

Disable-OOBEPrivacy

Set-RunOnce

Set-Bitlocker

Remove-Hybrid

Remove-ADJoin
