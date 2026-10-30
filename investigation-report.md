# Investigation Report: Brute Force Compromise of WS-FINANCE-03

**Analyst:** Brandon Griffith
**Date of events:** October 12, 2026
**Source:** Windows Security event log export, WS-FINANCE-03 (33 events reviewed)
**Tooling:** event_log_analyzer.py (this repository), manual timeline review

## Summary

Between 13:22 and 13:24 on October 12, an external source at 203.0.113.45 ran a password guessing attack against WS-FINANCE-03. After failures against the built-in administrator account, the attack succeeded against the user account j.miller, which holds administrative privileges. In the following twelve minutes the session installed a new service and created a new user account, both consistent with an attacker setting up persistence. The workstation should be treated as compromised.

## Timeline (all times October 12, 2026)

| Time | Event | Detail |
| --- | --- | --- |
| 07:58 | 4624 / 4672 | s.admin logs on at DC-01 from the internal admin host. Normal. |
| 08:01 | 4624 / 4672 | j.miller logs on to WS-FINANCE-03 from 192.168.56.20. Normal work start. |
| 08:14 | 4625, then 4624 | One failed logon for j.miller from the internal address, followed by a success. A mistyped password; below threshold, no action. |
| 13:22:41 to 13:22:56 | 4625 x6 | Six failed logons against **administrator** from 203.0.113.45. Password guessing begins. |
| 13:23:31 to 13:23:49 | 4625 x7 | Seven failed logons against **j.miller** from the same external address. |
| 13:24:05 | 4624 | **Successful logon for j.miller from 203.0.113.45.** The guess worked. |
| 13:24:06 | 4672 | Special privileges assigned to that session. The compromised account is an administrator. |
| 13:31:18 | 7045 | A new service is installed on WS-FINANCE-03. Consistent with persistence. |
| 13:36:52 | 4720 | A new user account is created. Consistent with a backdoor account. |
| 17:03 | 4624 | j.miller logs on from the internal address again. It cannot be assumed this session was the legitimate user acting safely; the credential must be treated as burned. |

## Findings

1. **The attack is external and targeted.** Every malicious event comes from one address, 203.0.113.45, in a tight two minute window, against two named accounts. This is not scanning noise.
2. **The compromised account is privileged.** Event 4672 one second after the successful logon shows the session received special privileges, so the attacker had administrative control of the workstation.
3. **Persistence was established.** A service install (7045) and an account creation (4720) within twelve minutes of the breach are the classic second step after a password compromise.
4. **Normal traffic explains the rest of the log.** The morning administrator logons and the single 08:14 failure match ordinary use and are not part of the incident. Separating these from the attack is what keeps the report credible.

## Indicators

- Source address: 203.0.113.45 (documentation range used for this lab)
- Accounts targeted: administrator, j.miller
- Affected host: WS-FINANCE-03
- Event pattern: 4625 burst, 4624, 4672, 7045, 4720

## Recommendations

1. Isolate WS-FINANCE-03 from the network and preserve its logs and disk image before remediation.
2. Disable the new account created at 13:36 and remove the service installed at 13:31 after forensic review.
3. Force a password reset for j.miller and review every system where that credential was used; treat the administrator account the same way, since it was targeted.
4. Block or alert on remote logons from outside the organization to workstation class machines; interactive logons (type 10) from the internet should not be possible.
5. Turn on account lockout policy and alerting at five failed logons, the same threshold this analyzer uses, so the next burst pages an analyst instead of being found in a daily review.
6. Require MFA for any remote access path. A password alone is what failed here.

## Analyst note

Detection here did not depend on any single event. One failed logon is a typo. Thirteen failures in a minute, a success, privilege use, a service, and a new account, in that order, is a story, and the sequence is the evidence.
