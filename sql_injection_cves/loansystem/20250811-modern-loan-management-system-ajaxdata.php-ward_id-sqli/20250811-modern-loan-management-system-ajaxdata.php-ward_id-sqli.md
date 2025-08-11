# Exploit Title: Modern Loan Management System – SQL Injection in ajaxData.php (`http://localhost/loansystem/Source_Code/admin/ajaxData.php`)

**Date:** 2025-08-11  
**Exploit Author:** Anonymous  
**Vendor Homepage:** https://www.sourcecodester.com/users/mayurik  
**Software Link:** https://www.sourcecodester.com/php/14570/modern-loan-management-system-project-phpmysql-full-source-code.html  
**Version:** 1.0  
**Tested on:** PHP 7.4 on Ubuntu 20.04  

---

## Summary

A SQL Injection vulnerability exists in the `ajaxData.php` endpoint of **Modern Loan Management System**. Unsanitized user input in the specified parameter is interpolated directly into an SQL query, allowing attackers to infer or extract data and, in some cases, execute stacked/time-based payloads.  
**Back-end DBMS (as detected):** MySQL >= 5.0.12 (MariaDB fork)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** High (placeholder — adjust once CVSS is computed)

## Affected Component & Parameter

### Affected Endpoint

- **URL:** `http://localhost/loansystem/Source_Code/admin/ajaxData.php`
- **HTTP Method:** POST
- **Vulnerable File:** `ajaxData.php`
- **Parameter:** `ward_id`
- **Vector Location:** POST

### Injection Techniques (as identified by sqlmap)
- **Type:** time-based blind
  - **Title:** MySQL >= 5.0.12 AND time-based blind (query SLEEP)
  - **Payload:** `ward_id=1 AND (SELECT 8421 FROM (SELECT(SLEEP(5)))vwmQ)`
- **Type:** UNION query
  - **Title:** Generic UNION query (NULL) - 3 columns
  - **Payload:** 
```
ward_id=1 UNION ALL SELECT NULL,CONCAT(0x7178767871,0x684e765777454d6e5a73466a464f7a564c6e7a4a677050524f486943537675524d79684379776f58,0x7162626271),NULL-- -
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

1. Browse to `http://localhost/loansystem/Source_Code/admin/ajaxData.php`.  
2. Intercept the request and inject the provided payload(s) into parameter `ajaxData.php??<param>=...`.  
3. Observe conditional responses / time delays / injected row reflections per technique above.  
4. Confirm DBMS fingerprinting and data extraction as permitted by the app’s DB privileges.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


References
OWASP: SQL Injection Prevention Cheat Sheet

CWE-89: SQL Injection
