# Test Suite

All `*-test.toit` files in `tests/` are run on the host via `make test`
(excluding `tests/hw/`, which targets real ESP32 hardware).

> **Note:** Several tests import from `mdns.private.*` to verify internal state
> machines, caching, and wire serialization. External applications should only
> import `mdns.client`, `mdns.service`, and `mdns.api.mdns-service`.

## RFC 6762 / RFC 6763 Coverage Map

| RFC Section | Topic | Test File(s) |
|:---|:---|:---|
| 6762 §4 | `.local` & `.arpa` lookup scope | `audit-p5-p7-test.toit` |
| 6762 §5.4 | `QU` quarter-TTL unicast rule | `rfc-compliance-test.toit` |
| 6762 §6 | Source port 5353 check, rate limit, 20–120ms shared delay | `rfc-compliance-test.toit`, `audit-p5-p7-test.toit` |
| 6762 §6.1 | Restricted-form `NSEC` negative answers & A additionals | `security-and-rfc-fixes-test.toit`, `query-response-test.toit`, `audit-p5-p7-test.toit` |
| 6762 §6.7 | Legacy unicast responses (`TTL <= 10`, ID, questions, rate limit) | `query-response-test.toit`, `audit-p5-p7-test.toit` |
| 6762 §7.1 | Known-Answer suppression (`>= 50%` TTL, matching RDATA) | `rfc-compliance-test.toit`, `query-response-test.toit`, `audit-p5-p7-test.toit` |
| 6762 §7.2 | Split Known-Answer query `TC` bit | `audit-regressions-test.toit` |
| 6762 §7.4 | Duplicate-PTR suppression | `audit-p5-p7-test.toit` |
| 6762 §8.1–§8.5 | Probing jitter, Authority tiebreak, deferral, pre-probe ignore, announcements | `rfc-compliance-test.toit`, `probing-tiebreaking-test.toit`, `audit-regressions-test.toit` |
| 6762 §9 | Same-rrtype conflict detection, re-probing, renaming | `conflict-defense-test.toit`, `hostname-conflict-test.toit`, `service-conflict-test.toit`, `audit-regressions-test.toit` |
| 6762 §10.1–§10.2 | `TTL=0` goodbyes, 1s grace retention, `cache-flush` | `cache-test.toit`, `security-and-rfc-fixes-test.toit`, `audit-p5-p7-test.toit` |
| 6762 §11 | Local-source filtering | `audit-p5-p7-test.toit` |
| 6762 §16 | Case-insensitive ASCII name matching & case preservation | `cache-test.toit`, `query-response-test.toit`, `security-and-rfc-fixes-test.toit` |
| 6762 §17 | MTU packet size splitting | `audit-regressions-test.toit` |
| 6762 §18 | Header `OPCODE`/`RCODE` rejection, `Z`/`AD`/`CD` tolerance, parser fuzzing | `lenient-parser-test.toit`, `security-and-rfc-fixes-test.toit`, `parser-corpus-test.toit` |
| 6763 §6–§12 | Service types, instance names, TXT validation, `_services._dns-sd._udp.local`, additionals | `service-discovery-test.toit`, `query-response-test.toit`, `audit-regressions-test.toit` |
