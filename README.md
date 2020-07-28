# ClashofSpamTitan

This repository contains two scripts and the respective Pipenv environments to launch the PoC exploits against Spam Titan Gateway (version 7.07).
The following CVEs can be exploited with these two scripts:
* CVE-2020-11698: Unauthenticated Remote Code Execution through snmp-x.php.
* CVE-2020-11699: Authenticated RCE in certs-x.php abusing "fname" and php system() function.
* CVE-2020-11700: Access to arbitrary files in the file system.
* CVE-2020-11803: Authenticated RCE in mailqueue.php abusing parameter "jaction" and php eval() function.
* CVE-2020-11804: Authenticated RCE in mailqueue.php abusing "qid" parameter and php system() function.


