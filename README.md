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
alert tcp any any -> any any (msg:"SQLi Attempt 1"; content"or 1=1"; sid: 1000022
alert tcp any any -> any any (msg:"SQLi Attempt 1"; content"union select 1"; sid: 1000023
alert tcp any any -> any any (msg:"SQLi Attempt 1"; content:"union all select 1"; sid: 1000024
alert tcp any any -> any any (msg:"SQLi Attempt 1"; content:"order by 1"; sid: 1000025
alert tcp any any -> any any (msg:"SQLi Attempt 1"; content:"group by username"; sid: 1000026
alert tcp any any -> any any (msg:"SQLi Attempt 1"; content:"group by password"; sid: 1000027

# based boelan
alert tcp any any -> any any (msg:"Sqli Attempt with RegEx 1; pcre:"/or \[d]+=[\d]*/i"; sid: 1000019; rev:1;)
alert tcp any any -> any any (msg:"Sqli Attempt with RegEx 1; pcre:"/\' or \'[A-Za-z0-9]*\'=\'/i"; sid: 1000020; rev:1;)
alert icmp any any -> any any (msg:"no more ping"; sid:1000021;)
```
