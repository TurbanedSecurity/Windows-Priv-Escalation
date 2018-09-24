# Windows-Priv-Escalation

->Windows Unquoted Service Paths
Basically, it is a vulnerability that occurs if a service executable path is not enclosed with quotation marks and contains space.
To identify these unquoted services you can run this command on Windows Command Shell:
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
https://medium.com/@harshaunsingh/windows-privileged-escalation-manual-and-using-metasploit-framework-ch-1-fd5f31a7db86

->Raw passwords in registry
# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"
# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

->Identify hotfix or patches
systeminfo
# or
wmic qfe get Caption,Description,HotFixID,InstalledOn

->searching for cleartext passwords
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini
#Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*
# Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*

->mimikatz
extract cleartext passwords from memory

->llmnr/netbios poisining
use RESPONDER(Kali linux)





thanks----
https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html
https://medium.com/@rahmatnurfauzi/windows-privilege-escalation-scripts-techniques-30fa37bd194
http://www.fuzzysecurity.com/tutorials/16.html
