# PowerShell Commands

Useful PowerShell one-liner (and some two-liner) commands.

## Table of Contents

* [Active Directory User Commands](#active-directory-user-commands)
  * [Getting Started](#getting-started)
  * [Specific User Scenarios](#specific-user-scenarios)
* [Computer Object Commands](#computer-object-commands)
* [File Level Commands](#file-level-commands)

## Active Directory User Commands

### Getting Started

Before running any Active Directory commands, you need to import the correct module.

Import Active Directory Module

``` powershell
Import-Module ActiveDirectory
```

Get All Active Directory Module Commands

``` powershell
get-command -module ActiveDirectory
```

### Specific User Scenarios

Get All AD Information on a User in the Current Domain (the one you are running this from)

``` powershell
Get-ADUser -Identity <username> -properties *
```

Get All AD Information on a User in a Different Domain (assumes you have trust and permissions to access)

``` powershell
Get-ADUser -Identity <username> -server "domain" -properties *
```

Get All Members of a Group by name and ID

``` powershell
Get-ADGroupMember -Identity <group_name> -Recursive | select name,SamAccountName
```

Find All Groups a User is a Member of

``` powershell
Get-ADPrincipalGroupMembership <username> | select name
Get-ADPrincipalGroupMembership <username> -server "domain" | select name | Sort-Object -Property name
```

Add Member to an AD Group

``` powershell
Add-ADGroupMember -identity "<group_name>" -Member "<user_id>"
```

Remove Member from an AD Group

``` powershell
Remove-ADGroupMember -identity "<group_name>" -Member "<user_id>"
```

Find all users that are disabled

``` powershell
Search-ADAccount -AccountDisabled -UsersOnly | Format-Table Name,SamAccountName ObjectClass -A
```

Find the Date/Time for When an Account Expires

``` powershell
[datetime](Get-ADuser <userid> -Properties accountExpires).accountExpires
```

Find all Users with Locked Out Accounts

``` powershell
Search-ADAccount -LockedOut | select name, samAccountName
Search-ADAccount -LockedOut | Where-Object {$_.DistinguishedName -like "*DC=domain,DC=com"} | Select Name, LockedOut, LastLogonDate, PasswordExpired | Format-Table -AutoSize
```

Get AD User Information for List of Users and Output to CSV

``` powershell
Get-Content C:\<path>\users.txt | % {Get-ADUser -Identity $_ -properties * | select CN, samAccountName, EmployeeID, enabled, Description, Department, mlSubLobDescr, OfficePhone, Manager ,StreetAddress, LastLogonDate, LastBadPasswordAttempt, PasswordExpired} | Export-Csv C:\<path>\user_lookup.csv
```

Get AD User Group Membership Information for List of Users and Output to CSV

``` powershell
Get-Content C:\<path>\users.txt | % {Get-ADPrincipalGroupMembership $_ | select name} | Export-Csv C:\<path>\user_group_membership_lookup.csv
```

Get All Users of AD Groups for List of Groups and Output to CSV

``` powershell
$groups = Get-Content C:\<path>\groups.txt

foreach ($group in $groups) {
Get-ADGroupMember -Identity $Group | select @{Expression={$Group};Label="Group Name"},Name,SamAccountName | Export-CSV C:\<path>\user_groups.csv -NoTypeInformation -append
}
```

Get All Users of AD Groups Matching a Certain Name Format (i.e group name is like Local Admin)

``` powershell
$groups = Get-ADGroup -Filter {name -like "*Admin*"}

foreach ($group in $groups)
    {
    Get-ADGroupMember -Identity $Group -Server "domain" | Get-ADUser -Properties * | select @{Expression={$Group};Label="Common Name"},Name,enabled,LastLogonDate,GivenName,Surname,EmailAddress,title,department,mlSubLobDescr | Export-Csv C:\<path>\local_admin_group.csv -NoTypeInformation -Append
    }
```

Find user information by AD attribute (i.e. DisplayName)

``` powershell
Get-ADUser -Filter {DisplayName -like "*Bobby Administrator*"} -Properties * | Select name, DisplayName, EmailAddress, enabled, LastLogonDate, title, department, mlSubLobDescr | Format-Table -AutoSize
```

## Computer Object Commands

Find a Specific Service on a Computer using WMI

``` powershell
get-wmiobject -query "SELECT * FROM Win32_Process where Name = '<service_name.exe>'" | select-object Name,CommandLine | Sort-Object -Descending Name
```

Find Computers by Operating System Type

```powershell
Get-ADComputer -Filter * -Properties OperatingSystem | Select OperatingSystem -unique | Sort OperatingSystem
```

List all Servers in a Domain

``` powershell
Get-ADComputer -Server "domain.com" -Filter {operatingsystem -like "*server*"} -Properties * | select enabled,name,operatingsystem,canonicalname,lastlogondate | Export-Csv C:\<path>\computer_list.csv -Append -NoClobber
```

List all Servers in a Domain, but only return Enabled Computer Objects, and only return those logged into within the last 60 days from the current date, and only show the top 10 rows

``` powershell
Get-ADComputer -Server "domain.com" -Filter {(operatingsystem -like "*server*") -and (enabled -eq "TRUE")} -Properties * | where {$_.LastLogonDate -ge (Get-Date).AddDays(-60)} | select enabled,name,operatingsystem,canonicalname,lastlogondate | Format-Table -AutoSize | select -First 10
```

Find All Domain Controllers in a Specific Domain

``` powershell
Get-ADDomainController -Filter * -server <domain> | Select-Object name, domain
```

Find Out Information About a Specific Computer by Hostname

``` powershell
Get-ADComputer -Filter {Name -Like "<hostname>"} -Property * | Format-Table Name,ipv4address,OperatingSystem,OperatingSystemServicePack,LastLogonDate -Wrap -Auto
```

Find Host Information from TXT File of Hosts

``` powershell
Get-Content C:\<path>\file.txt | % {Get-ADComputer -Identity $_ -server <domain> -properties * | select name, ipv4address, operatingsystem, distinguishedname} | Export-Csv C:\<path>\output.csv -Append -NoClobber
```

Get the CN and DN for each Organizational Unit in a Specific Domain

``` powershell
Get-ADOrganizationalUnit -server "domain.com" -Filter * -Properties CanonicalName | Select-Object -Property CanonicalName, DistinguishedName | Sort-Object CanonicalName, ascending
```

Get All Computer Objects in a Particular OU in a Particular Domain

``` powershell
Get-ADComputer -server "domain.com" -SearchBase 'OU=NA,OU=USA,OU=HQ,DC=domain,DC=com' -Filter '*' -Properties * | Select name, ipv4address, operatingsystem, CanonicalName, distinguishedname | Format-Table -AutoSize
```

Get All Computer Objects from a TXT File of OUs

``` powershell
Get-Content C:\<path>\computer_ous.txt | % {Get-ADComputer -Server "domain.com" -SearchBase $_ -Filter '*' -Properties * | Select name,ipv4address,operatingsystem,CanonicalName,distinguishedname,enabled} | Export-Csv C:\<path>\computers_in_ous.csv -Append -NoClobber
```

## File Level Commands

Recursively Remove Files Older than a Certain Day in a Directory

``` powershell
Get-ChildItem -Path "C:\<path>\<dir>\" -Recurse | Where-Object CreationTime -gt (Get-Date).AddDays(-180) | Remove-Item -Recurse
```
