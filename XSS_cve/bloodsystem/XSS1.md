## Exploit Title: Blood System – Stored XSS via `don.php` (`http://localhost/bloodsystem/BBfile/don.php` → `profile.php`)

**Date:** 2025-08-24 \
**Exploit Author:** Anonymous \
**Vendor Homepage:** N/A (local project) \
**Software Link:** N/A (local project) \
**Version:** N/A \
**Tested on:** PHP 7.x on Ubuntu 20.04 

---

## Summary

A **Stored Cross-Site Scripting (XSS)** vulnerability exists. The **`city`** field in `don.php` is stored and later rendered in `profile.php` without sanitization.

**CWE:** CWE-79 (Stored XSS)
**Severity:** High

## Affected Component & Parameter

* **Source:** `don.php` (POST param `city`)
* **Sink:** `profile.php`

## XSS Type & Example Payloads

```html
<script>alert('xss-bloodsystem')</script>
```

```
" autofocus onfocus=alert('xss') x=
```

```html
<img src=x onerror=alert('xss')>
```

## Rendered XSS Evidence

![xss-render](sqlmap_summary.png)

## Technical Description

The `city` parameter is persisted and rendered unescaped in `profile.php`, causing persistent XSS.

## Impact

* Script executes for all viewers
* Credential theft and privilege abuse possible

## Steps to Reproduce

1. Submit payload in `city` field at `don.php`.
2. View `profile.php`.
3. Observe alert execution.

## Vulnerable Code (Screenshot)

![vulnerable-code](code_snippet.png)


