# Exploit Title: blood-bank-system – SQL Injection in delete.php (`http://localhost/bloodsystem/BBfile/admin/delete.php`)

**Date:** 2025-08-11  
**Exploit Author:** Anonymous  
**Vendor Homepage:** https://code-projects.org/  
**Software Link:** https://code-projects.org/blood-bank-system-in-php-with-source-code/  
**Version:** 1.0  
**Tested on:** PHP 7.4 on Ubuntu 20.04  

---

## Summary

A SQL Injection vulnerability exists in the `delete.php` endpoint of **blood-bank-system**. Unsanitized user input in the specified parameter is interpolated directly into an SQL query, allowing attackers to infer or extract data and, in some cases, execute stacked/time-based payloads.  
**Back-end DBMS (as detected):** MySQL >= 5.1 (MariaDB fork)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** High (placeholder — adjust once CVSS is computed)

## Affected Component & Parameter

### Affected Endpoint

- **URL:** `http://localhost/bloodsystem/BBfile/admin/delete.php`
- **HTTP Method:** POST
- **Vulnerable File:** `delete.php`
- **Parameter:** `search`
- **Vector Location:** POST

### Injection Techniques (as identified by sqlmap)
- **Type:** boolean-based blind
  - **Title:** MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause
  - **Payload:** `search=test' RLIKE (SELECT (CASE WHEN (6181=6181) THEN 0x74657374 ELSE 0x28 END)) AND 'EhID'='EhID`
- **Type:** error-based
  - **Title:** MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
  - **Payload:** `search=test' AND EXTRACTVALUE(8620,CONCAT(0x5c,0x7170717a71,(SELECT (ELT(8620=8620,1))),0x7170707a71)) AND 'yzHc'='yzHc`
- **Type:** time-based blind
  - **Title:** MySQL >= 5.0.12 AND time-based blind (query SLEEP - comment)
  - **Payload:** `search=test' AND (SELECT 7501 FROM (SELECT(SLEEP(5)))UeSy)#`



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

1. Browse to `http://localhost/bloodsystem/BBfile/admin/delete.php`.  
2. Intercept the request and inject the provided payload(s) into parameter `delete.php??<param>=...`.  
3. Observe conditional responses / time delays / injected row reflections per technique above.  
4. Confirm DBMS fingerprinting and data extraction as permitted by the app’s DB privileges.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


References
OWASP: SQL Injection Prevention Cheat Sheet

CWE-89: SQL Injection
