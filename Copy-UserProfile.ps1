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

.\robocopy $ProfileFolder $Destination /E /XC /XN /XO /r:0 /XD "$ProfileFolder\Appdata" 

#.\robocopy $ProfileFolder $Destination /NDL /NJH /NJS /E /XC /XN /XO /r:0 /XD "$ProfileFolder\Appdata" | ForEach-Object{$data = $_.Split([char]9); if("$($data[4])" -ne "") { $file = "$($data[4])"} ;Write-Progress "Percentage $($data[0])" -Activity "Robocopy" -CurrentOperation "$($file)"  -ErrorAction SilentlyContinue; }

}


$ProfileFolder = Get-Folder
$Destination = $env:USERPROFILE

Set-Owner

Copy-Folder
