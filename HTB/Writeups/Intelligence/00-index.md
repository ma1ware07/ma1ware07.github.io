---
tags:
  - windows 
  - medium
  - silver ticket
  - ad
  - smb
  - spraying
  - kerberos
  - gmsa
---

# Introduction

Intelligence was an medium-level box that showcased realistic AD-attacks. 

Initially we find a web-server with two pdfs in the format of 2020-Month-Day so we create a bruteforce script to download any other pdfs not linked directly. After this we extract a list of usernames from the pdfs as well as a default password which we then use to password spray using crackmapexec. 
This returns a hit on a Tiffany.Molina who has access to the user.txt as well as to the IT share which contains a powershell script that runs every 5 minutes. We then add a DNS record using the default credentials we recovered, get a set of new credentials. Use new credentials to read the hashed password of a service-user which we can then use in a silver-ticket type of attack and impersonate the Administrator.  

![[Machines/Intelligence/01-recon|01-recon]]

![[Machines/Intelligence/02-exploitation|02-exploitation]]