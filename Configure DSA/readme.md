# Configure MDI DSA

## GMSA
```powershell
# Declare the identity (e.g., service account, user, or group) that you want to grant read access to the Deleted Objects container:
$Identity = 'mdiSvc01'
# If the specified identity is a gMSA (Group Managed Service Account), 
# first create a security group and add the gMSA to this group. This is 
# because gMSAs cannot directly be assigned permissions in all contexts.
$groupName = 'mdiUsr01Group'
$groupDescription = 'Members of this group are allowed to read the objects in the Deleted Objects container in AD'
# Check if the identity is a gMSA by attempting to retrieve the service account.
if(Get-ADServiceAccount -Identity $Identity -ErrorAction SilentlyContinue) {
    # Parameters for the new security group
    $groupParams = @{
        Name           = $groupName
        SamAccountName = $groupName
        DisplayName    = $groupName
        GroupCategory  = 'Security'
        GroupScope     = 'Universal'
        Description    = $groupDescription
    }
    # Create the security group and store its object
    $group = New-ADGroup @groupParams -PassThru
    # Add the gMSA to the newly created group
    Add-ADGroupMember -Identity $group -Members ('{0}$' -f $Identity)
    # Set the Identity variable to the group name for permission assignment
    $Identity = $group.Name
}
# Retrieve the distinguished name (DN) of the current Active Directory domain
# This is used to construct the DN of the Deleted Objects container
$distinguishedName = ([adsi]'').distinguishedName.Value
# Construct the distinguished name for the Deleted Objects container
$deletedObjectsDN = 'CN=Deleted Objects,{0}' -f $distinguishedName
# Take ownership of the Deleted Objects container to ensure we can modify its permissions.
# The `dsacls` command is used to change permissions of AD objects.
# Build the command parameters for taking ownership
$params = @("$deletedObjectsDN", '/takeOwnership')
# Execute the command to take ownership
C:\Windows\System32\dsacls.exe $params
# Grant the 'List Contents' (L) and 'Read Property' (RP) permissions to the specified identity.
# These permissions allow the identity to view and read properties of the deleted objects in AD.
# Build the command parameters for granting these permissions
$params = @("$deletedObjectsDN", '/G', ('{0}\{1}:LCRP' -f ([adsi]'').name.Value, $Identity))
# Execute the command to grant the permissions
C:\Windows\System32\dsacls.exe $params
# To remove the previously granted permissions, uncomment these next two lines 
# and run them instead of the two lines above. This effectively revokes the
# 'List Contents' and 'Read Property' permissions from the identity.
# $params = @("$deletedObjectsDN", '/R', ('{0}\{1}' -f ([adsi]'').name.Value, $Identity))
# C:\Windows\System32\dsacls.exe $params
```

## Normal domain account
