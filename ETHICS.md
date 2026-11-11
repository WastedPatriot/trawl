# Authorised use

trawl runs real scanners. Point it at machines you own, a lab you were given, or an HTB box on the HTB network. "I was curious about this random IP" is not a scope.

A scope file is a seatbelt, not a lawyer. If you pass one, trawl refuses anything that doesn't match, and it does not resolve DNS to sneak a name into a CIDR. You are still the person who pressed enter.

There is no telemetry and no update check of trawl's own. nuclei is started with its update check off so a lab run doesn't wander off to the internet on your behalf. Don't put secrets in target files; they end up in the report, because that's the point of a report.
