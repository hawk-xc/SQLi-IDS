# SQLi-IDS
SQLi-intrusion detection system dengan menggunakan tools snort pada server

```bash
nano /etc/snort/rules/local.rules
```
```
# based sqli
alert tcp any any -> any 80 (msg: "Error Based SQL Injection Detected"; content: "%27" ; sid:1000011; )
alert tcp any any -> any 80 (msg: "Error Based SQL Injection Detected"; content: "%22" ; sid:1000012; )
alert tcp any any -> any 80 (msg: "AND SQL Injection Detected"; content: "and" ; nocase; sid:1000013; )
alert tcp any any -> any 80 (msg: "OR SQL Injection Detected"; content: "or" ; nocase; sid:1000014; )
alert tcp any any -> any 80 (msg: "AND SQL Injection Detected"; content: "%26%26" ; sid:1000015; )
alert tcp any any -> any 80 (msg: "OR SQL Injection Detected"; content: "%7C%7C" ; sid:1000016; )
alert tcp any any -> any 80 (msg: "Order by SQL Injection"; content: "order" ; sid:1000000017; )
alert tcp any any -> any 80 (msg: "UNION SELECT SQL Injection"; content: "union" ; sid:1000018; )

# based union sqli
alert tcp any any -> any any (msg:"SQLi Attempt 1"; content"or 1=1"; sid: 1000022;)
alert tcp any any -> any any (msg:"SQLi Attempt 1"; content"union select 1"; sid: 1000023;)
alert tcp any any -> any any (msg:"SQLi Attempt 1"; content:"union all select 1"; sid: 1000024;)
alert tcp any any -> any any (msg:"SQLi Attempt 1"; content:"order by 1"; sid: 1000025;)
alert tcp any any -> any any (msg:"SQLi Attempt 1"; content:"group by username"; sid: 1000026;)
alert tcp any any -> any any (msg:"SQLi Attempt 1"; content:"group by password"; sid: 1000027;)

# based boelan
alert tcp any any -> any any (msg:"Sqli Attempt with RegEx 1; pcre:"/or \[d]+=[\d]*/i"; sid: 1000019; rev:1;)
alert tcp any any -> any any (msg:"Sqli Attempt with RegEx 1; pcre:"/\' or \'[A-Za-z0-9]*\'=\'/i"; sid: 1000020; rev:1;)
alert tcp any any -> any 6200 (msg:"SQLi Attempt with RegEx 1"; flow:established,to_server; pcre:"/((\?)[^\n]*(\=)[^\n]*((\%55)|(u)|(\%75))((\%4e)|(n)|(\%6e))((\%69)|(i)|(\%49))((\%6f)|(o)|(\%4f))((\%4e)|(n)|(\%6e)))/i" ; classtype: Web-application-attack; sid:1000021; rev:1;)
alert tcp any any -> any 6200 (msg:"Blind SQL Injection – Boolean - SQL"; flow:established,to_server; pcre: "/((\?)[^\n]*(\=)[^\n*]*((\%41)|(a)|(\%61))((\%4e)|(n)|(\%6e))((\%44)|(d)|(\%64)))/i" ; classtype: Web-application-attack; sid:1000022; rev:1;)

# xss reflected
alert tcp any any -> any 6200 (msg:"Cross Site Scripting - XSS - Reflected"; flow:established,to_server; pcre: "/((\?)v(\=)\d\.\d((%3c)script(%3e))[^\n]*((%3c)(%2f)script(%3e)))/i"; classtype: Web-application-attack; sid:1000023; rev:1;)

# xss stored
alert tcp any any -> any 6200 (msg:"Cross Site Scripting - XSS - Stored"; flow:established,to_server; pcre: "/((\?)comment(\=)[^\n]*((%3c)script(%3e))[^\n]*((%3c)(%2f)script(%3e)))/i" ; classtype: Web-application-attack; sid:1000024; rev:1;)

# xss jsonnp attack
alert tcp any any -> any 6200 (msg:"Cross Site Scripting - XSS - JSONP"; flow:established,to_server; pcre: "/(users\.json(\?)callback=alert((%28)|(\())(%22arbitrary.*javascript%22)((%29)|(\)))(%3b)process)/i" ; classtype: Web-application-attack; sid:1000025; rev:1;)

# ping imcp allert
alert icmp any any -> any any (msg:"no more ping"; sid:1000026;)

# nmap scan alert
alert icmp any any -> 192.168.1.105 any (msg: “NMAP ping sweep Scan”; dsize:0;sid:10000004; rev: 1; )
```
