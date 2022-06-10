REM This batch file will setup external time servers that the domain can sync with***

net stop w32time
w32tm /config /syncfromflags:manual /manualpeerlist:'0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org,3.pool.ntp.org'
w32tm /config /reliable:yes
net start w32time
w32tm /query /configuration

REM You can verify results above and manually close this Window***

Pause 10
Exit

REM  To force synchronization -   net time \\<domainserver or IP> /set /y



