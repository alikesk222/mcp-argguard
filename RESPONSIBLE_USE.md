# Responsible use

mcp-argguard is a defensive control layer. It is not a security guarantee and it is not an exploit tool. Use it only on MCP clients and servers you are authorized to protect. It does not ship attack payloads, and it does not replace patches: upgrade affected servers.

## What this repository will not accept

- Working exploits, offensive payloads, or proof-of-concept commands that run code on a real host.
- Tests or fixtures that contact a network target, a cloud metadata address, or a production MCP server.
- Copies of malicious instruction text, even as a regression fixture. Packs describe the class of follow-on tool call and drive that call from a scripted client.
- Launch-guard cases that spawn a process. The classifier is pure. Case files use an inert token such as `marker`.
- Credentials. The fixture `.env` used by tests is `CANARY=fake-canary-not-a-credential`. The AWS example key `AKIAIOSFODNN7EXAMPLE` is the public documentation key.

Regression tests talk only to local mock MCP servers in this repository.

## What a policy pack is

A pack is an example of a boundary: which tool arguments may pass. It is not a claim that the named product is safe when the pack allows a call, and it is not a patch. Names taken from an advisory are labeled as advisory-sourced when this repository has not re-parsed the server's tool schema.

## Reporting

Vulnerability reports go through [GitHub private vulnerability reporting](https://github.com/alikesk222/mcp-argguard/security/advisories/new). See [SECURITY.md](SECURITY.md). Do not open a public issue with a bypass.
