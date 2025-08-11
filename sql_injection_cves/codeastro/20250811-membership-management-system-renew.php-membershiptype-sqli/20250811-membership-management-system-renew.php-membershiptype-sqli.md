# Exploit Title: Membership Management System – SQL Injection in renew.php (`http://localhost/codeastro/renew.php`)

**Date:** 2025-08-11  
**Exploit Author:** Anonymous  
**Vendor Homepage:** https://codeastro.com/  
**Software Link:** https://codeastro.com/membership-management-system-in-php-with-source-code/  
**Version:** 1.0  
**Tested on:** PHP 7.4 on Ubuntu 20.04  

---

## Summary

A SQL Injection vulnerability exists in the `renew.php` endpoint of **Membership Management System**. Unsanitized user input in the specified parameter is interpolated directly into an SQL query, allowing attackers to infer or extract data and, in some cases, execute stacked/time-based payloads.  
**Back-end DBMS (as detected):** MySQL < 5.0.12 (MariaDB fork)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** High (placeholder — adjust once CVSS is computed)

## Affected Component & Parameter

### Affected Endpoint

- **URL:** `http://localhost/codeastro/renew.php`
- **HTTP Method:** POST
- **Vulnerable File:** `renew.php`
- **Parameter:** `membershipType`
- **Vector Location:** POST

### Injection Techniques (as identified by sqlmap)
- **Type:** time-based blind
  - **Title:** MySQL < 5.0.12 AND time-based blind (heavy query)
  - **Payload:** `membershipType=test WHERE 6299=6299 AND 2517=BENCHMARK(5000000,MD5(0x57574647))-- mvsb`



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

1. Browse to `http://localhost/codeastro/renew.php`.  
2. Intercept the request and inject the provided payload(s) into parameter `renew.php??<param>=...`.  
3. Observe conditional responses / time delays / injected row reflections per technique above.  
4. Confirm DBMS fingerprinting and data extraction as permitted by the app’s DB privileges.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


References
OWASP: SQL Injection Prevention Cheat Sheet

CWE-89: SQL Injection
