# Exploit Title: Hospital Management System – SQL Injection in get_doctor.php (`http://localhost/hospitalmanagementsystemproject4/hospital/hms/get_doctor.php`)

**Date:** 2025-08-11  
**Exploit Author:** Anonymous  
**Vendor Homepage:** https://github.com/kishan0725  
**Software Link:** https://github.com/kishan0725/Hospital-Management-System  
**Version:** 4.0  
**Tested on:** PHP 7.4 on Ubuntu 20.04  

---

## Summary

A SQL Injection vulnerability exists in the `get_doctor.php` endpoint of **Hospital Management System**. Unsanitized user input in the specified parameter is interpolated directly into an SQL query, allowing attackers to infer or extract data and, in some cases, execute stacked/time-based payloads.  
**Back-end DBMS (as detected):** MySQL >= 5.0.12 (MariaDB fork)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** High (placeholder — adjust once CVSS is computed)

## Affected Component & Parameter

### Affected Endpoint

- **URL:** `http://localhost/hospitalmanagementsystemproject4/hospital/hms/get_doctor.php`
- **HTTP Method:** POST
- **Vulnerable File:** `get_doctor.php`
- **Parameter:** `doctor`
- **Vector Location:** POST

### Injection Techniques (as identified by sqlmap)
- **Type:** boolean-based blind
  - **Title:** AND boolean-based blind - WHERE or HAVING clause
  - **Payload:** `doctor=1' AND 9669=9669-- UfJu`
- **Type:** time-based blind
  - **Title:** MySQL >= 5.0.12 AND time-based blind (query SLEEP)
  - **Payload:** `doctor=1' AND (SELECT 8407 FROM (SELECT(SLEEP(5)))TNvO)-- aMsu`
- **Type:** UNION query
  - **Title:** Generic UNION query (NULL) - 1 column
  - **Payload:** 
```
doctor=1' UNION ALL SELECT CONCAT(0x71716b7871,0x4f64756e796969614e6a7364644947697342517a674c457056786c70787769486d6a6d5176425677,0x7162767a71)-- -
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

1. Browse to `http://localhost/hospitalmanagementsystemproject4/hospital/hms/get_doctor.php`.  
2. Intercept the request and inject the provided payload(s) into parameter `get_doctor.php??<param>=...`.  
3. Observe conditional responses / time delays / injected row reflections per technique above.  
4. Confirm DBMS fingerprinting and data extraction as permitted by the app’s DB privileges.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


References
OWASP: SQL Injection Prevention Cheat Sheet

CWE-89: SQL Injection
