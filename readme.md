# Breaking Intune enrollment restrictions

## Introduction 
This write-up summarizes my work focused on Microsoft Intune’s Windows enrollment flow. The original goal was to identify attack paths in Intune device enrollment that could be used to gain initial access. As the work progressed, the focus shifted to understanding how enrollment state is established, which server-side validations gate enrollment, and where client-provided device context can influence outcomes. This write-up focuses on the technical findings around device context mutation and what that means for enrollment restrictions.
This work was completed during my internship at Bureau Veritas Cybersecurity for Fontys University of Applied Sciences.
## Prerequisites
Pytune was used to simulate theenrollment and create repeatable enrollment traffic. To observe the enrollment flow, the traffic was proxied through Burp Suite by using Python’s proxy option (-x):
```
pytune.py -x http://localhost:[port] entra_join -o Windows -d [REDACTED] -u Example@[REDACTED] -p [REDACTED]
```


