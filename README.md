                                                      Windows priv escalation
#Common Windows Privilege Escalation Vectors

1)Stored Credentials

2)Windows Kernel Exploit

3)DLL Injection

4)Unattended Answer File

5)Insecure File/Folder Permissions

6)Insecure Service Permissions

7)DLL Hijacking

8)Group Policy Preferences

9)Unquoted Service Path

10)Always Install Elevated

11)Token Manipulation

12)Insecure Registry Permissions

13)Autologon User Credential

14)User Account Control (UAC) Bypass

15)Insecure Named Pipes Permissions

--------------------------------Links and commands-----

->Windows Unquoted Service Paths
Basically, it is a vulnerability that occurs if a service executable path is not enclosed with quotation marks and contains space.
To identify these unquoted services you can run this command on Windows Command Shell:
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
https://medium.com/@harshaunsingh/windows-privileged-escalation-manual-and-using-metasploit-framework-ch-1-fd5f31a7db86

->Raw passwords in registry
#vnc
reg query "HKCU\Software\ORL\WinVNC3\Password"
#Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
#SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
#Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
#Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

->Identify hotfix or patches
systeminfo
#or
wmic qfe get Caption,Description,HotFixID,InstalledOn
post/windows/gather/enum_patches (metasploit module)

->searching for cleartext passwords
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini
#Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*
#Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*

->mimikatz
extract cleartext passwords from memory

->llmnr/netbios poisining
use RESPONDER(Kali linux)

->Using always installed elevated configuration
http://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/

->Using kernel exploits
http://www.hackingarticles.in/windows-kernel-exploit-privilege-escalation/

->Multiple ways to Bypass uac
http://www.hackingarticles.in/multiple-ways-to-bypass-uac-using-metasploit/

->Using automated scripts
https://medium.com/@rahmatnurfauzi/windows-privilege-escalation-scripts-techniques-30fa37bd194
http://www.hackingarticles.in/window-privilege-escalation-via-automated-script/
Includes Sherlock,JAWS,Windows Exploit suggester, Power Up

--------thanks----
https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html
https://medium.com/@rahmatnurfauzi/windows-privilege-escalation-scripts-techniques-30fa37bd194
http://www.fuzzysecurity.com/tutorials/16.html
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
