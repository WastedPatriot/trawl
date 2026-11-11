# Security

## Reporting

If you find a secret in the history, or a bug that would make trawl scan something it was told not to, use a [private advisory](https://github.com/WastedPatriot/trawl/security/advisories/new). Don't open a public issue with the secret, the payload, or a neat little proof pasted in.

If private advisories aren't switched on, open an issue that says you've found something and stop there. No snippet. I'll take it from the advisory.

A fixture that contains the characters `<script>` is a parser test. It is not a finding.

## Authorised use

trawl shells out to nmap, ffuf and nuclei. Those are real scanners. Point them at machines you own, a lab you were given, or an HTB box on the HTB network. "I was curious" is not a scope.

The scope file is a seatbelt, not a lawyer. The longer version is [ETHICS.md](ETHICS.md). Don't commit wordlists, target notes, or anything that looks like a key; the gitignore is there because people do.
