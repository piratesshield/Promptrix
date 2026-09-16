# Promptrix

<p align="center">
  <img src="logo.png" alt="Promptrix" width="380">
</p>

### GenAI Data Protection for the Browser

Employees paste source code, customer records and production credentials into ChatGPT.
Promptrix inspects that content **in the browser, before it reaches the provider** — masking
secrets in prompts, inspecting file uploads, and streaming every decision to your SIEM.

No proxy. No traffic interception. No TLS inspection. **Detection runs entirely on the endpoint.**

---

## Product summary

| | |
|---|---|
| **Deployment** | Chrome extension, Manifest V3 — unpacked or managed policy |
| **Coverage** | 8 hosts — ChatGPT · Gemini · Claude · Perplexity · Copilot |
| **Enforcement point** | The browser composer, pre-submit |
| **Detection engine** | 224 detectors · 165 enabled by default · on-device |
| **Content inspection** | 14 file signatures · recursive archive & document extraction |
| **Telemetry** | 8 SIEM wire formats · 6 auth modes · 7 event types |
| **Latency** | Sub-20 ms for a typical prompt; linear to input size |
| **Data residency** | Local by default — no egress unless you configure it |

---

## 1 · Data Loss Prevention

### 1.1 Detection coverage

**224 detectors** across five DPDP-aligned classifications.

| Classification | Detectors | Representative coverage |
|---|---:|---|
| **Authentication Secret** | **101** | AWS access & secret keys, GitHub PAT / fine-grained / OAuth, OpenAI, Anthropic, Google API & OAuth, Stripe live & test, Slack tokens & webhooks, Twilio, SendGrid, Mailgun, Square, Shopify, npm, Docker, DigitalOcean, Telegram, Discord, JWT, PEM/RSA/OpenSSH/PGP private keys, DB & storage connection strings, Azure Blob, bearer tokens, password assignments |
| **High-Risk Identifier** | **46** | Aadhaar, PAN, passport, driving licence, voter ID, national IDs, payment cards, IBAN, bank accounts, tax IDs |
| **Confidential** | **41** | Internal hostnames, cloud ARNs, infrastructure identifiers, legal & contract references, standards identifiers |
| **Special-Handling Data** | **23** | Health context, biometric references, minors, religion & caste |
| **Personal Data** | **13** | Email, phone, postal address, date of birth, UPI ID |
| **Total** | **224** | |

**Confidence tiering** — every detector is graded, and the low-confidence tier ships disabled so
the default policy does not generate noise:

| Tier | Count | Default | Behaviour |
|---|---:|---|---|
| Precise | 145 | **On** | Vendor-prefixed or structurally unambiguous (`AKIA…`, `sk-ant-…`) |
| Contextual | 15 | **On** | Requires a nearby keyword (`password=`, `OTP:`) |
| Candidate | 64 | **Off** | Bare digit/letter runs — enable deliberately |

**Deterministic validation** — 19 detectors verify a checksum before reporting, so a malformed
value is never raised:

| Algorithm | Applied to |
|---|---|
| Verhoeff | Aadhaar |
| Luhn | Payment cards |
| IBAN MOD-97 | International bank accounts |
| 16 inline heuristics | Hex-vs-hash discrimination, entropy floors, structural gates |

### 1.2 Policy actions

Four independent switches **per detector** — 224 × 4 controls:

| Action | Effect |
|---|---|
| **Detect** | Run this detector |
| **Mask** | Replace the matched value with `XXXXXX`, then send |
| **Block** | Stop the prompt; it is never submitted |
| **Warn** | Notify the user beside the composer |

Shipping default: **detect + mask + warn enabled, block disabled.** Masking rewrites the
composer and auto-submits the sanitized prompt, so the user's workflow is not interrupted.
Bulk enforcement applies an action across every enabled detector in one step.

### 1.3 Detection engineering

| Property | Guarantee |
|---|---|
| **Idempotent** | Sanitized output is inert — re-submitting a masked prompt is a no-op. Verified across 500 randomized multi-secret prompts, all converging in a single pass. |
| **Evasion-resistant** | A live secret written directly against a redaction run is still detected. |
| **Placeholder-aware** | Shannon entropy and character-class diversity suppress `AKIAIOSFODNN7EXAMPLE` and `.env.example` fixtures. |
| **Unicode-normalised** | NFC normalisation and zero-width character stripping defeat homoglyph bypass. |
| **Fail-closed** | If masking cannot be applied to a site's editor, the prompt is **held back, never sent unmasked**. |

**Per-site editor adapters.** Each AI application implements its composer differently and
requires a different write strategy. Every write is **verified by reading the value back**:

| Editor | Sites | Strategy |
|---|---|---|
| ProseMirror | ChatGPT, Claude | Synthetic paste event |
| Quill | Gemini | Synthetic paste event |
| React controlled input | Copilot, Perplexity | Value-tracker reset + native setter |

---

## 2 · Content Inspection (file uploads)

Attachments are inspected **before upload**. The engine does not trust the filename.

### 2.1 True file type resolution

Type is resolved from **magic bytes**, not the extension. **14 signatures**:

| Family | Types |
|---|---|
| Document | PDF, OLE (legacy Office) |
| Archive | ZIP (local + central directory), GZIP, 7-Zip, RAR |
| Image | PNG, JPEG, GIF |
| Media | RIFF |
| Executable | ELF, PE |
| Database | SQLite |

**Masquerade detection** — when the resolved type contradicts the declared extension
(`customers.png` that is actually a ZIP), the file is flagged as evasion and the risk score
is raised. This is the single strongest signal of deliberate exfiltration.

### 2.2 Recursive extraction

Content is unpacked and scanned **inside containers**, not merely at the surface:

| Container | Handling |
|---|---|
| **ZIP / OOXML** (`.docx` `.xlsx` `.pptx` `.odf`) | Central directory parsed, entries inflated via `deflate-raw`, XML parts converted to text |
| **GZIP** | Inflated and re-routed through type resolution |
| **PDF** | FlateDecode streams inflated, text operators extracted |
| **Nested archives** | Recursed to configurable depth |

Every extracted segment is scanned by the **same 224 detectors** used on prompts.

### 2.3 Resource budget

Inspection is bounded so a hostile or oversized archive cannot hang the tab:

| Control | Default |
|---|---|
| Maximum file size | 4,096 KB |
| Maximum inspection time | 4,000 ms |
| Maximum recursion depth | 3 |
| Maximum archive entries | 400 |
| Inspection depth | `Deep` · `Shallow` · `Off` |

Exceeding a budget yields a **partial verdict marked as truncated** — never a silent pass.

### 2.4 Risk scoring

Findings are scored into a band, rather than any single hit dictating the outcome:

| Factor | Contribution |
|---|---|
| Severity base | CRITICAL 40 · HIGH 25 · MEDIUM 10 · LOW 3 |
| Checksum-validated | +10 |
| Credential material | +20 to +30 |
| Compound identity (3+ correlated attributes) | +15 to +30 |
| Bulk exposure (25+ findings) | up to +25 |
| Type masquerade | +15 |

**Band floors** override arithmetic where policy demands it:

- A high-confidence credential alone forces **CRITICAL** — an API key is not a scoring input, it is a verdict.
- 100+ findings with 2+ distinct identity attributes forces **CRITICAL** as a reportable-scale event.

| Band | Score | Default action |
|---|---|---|
| **CRITICAL** | ≥ 80 | **Quarantine** — attachment detached |
| **HIGH** | ≥ 50 | Notify |
| **MODERATE** | ≥ 25 | Notify |
| **LOW** | ≥ 0 | Allow |

Each band is independently configurable to **Allow · Notify · Quarantine · Block**.
Files are SHA-fingerprinted for audit correlation.

---

## 3 · SIEM integration

Stream DLP decisions and prompt activity to any HTTP collector.

| Capability | Detail |
|---|---|
| **Wire formats** (8) | JSON · NDJSON · Splunk HEC · ArcSight CEF · QRadar LEEF 2.0 · Elastic ECS · **Coralogix** · **custom `%%field%%` template** |
| **Authentication** (6) | None · Bearer · Custom header · Basic · HMAC-SHA256 signature · Query parameter |
| **Event types** (7) | `dlp.mask` `dlp.block` `dlp.warn` `dlp.file` `policy.changed` `prompt.captured` `response.captured` |
| **Profiles** | Multiple concurrent destinations, each with its own format, auth and event subscription |
| **Reliability** | Batching, exponential-backoff retry, 500-event spool, per-profile health |
| **Content** | **Metadata-only by default** — inclusion is opt-in and visibly flagged |

The custom template renders an operator-authored body with `%%field%%` placeholders, the same
model FortiGate Security Fabric uses for automation stitches — set batch size to 1 for one
request per event.

> The forwarder is itself an egress path. Content inclusion is off by default for that reason.

---

## 4 · Prompt capture & recall

| Feature | Detail |
|---|---|
| **Auto-capture** | Every prompt and response, with the permanent conversation URL |
| **Prompt recall** | Past prompts surface as you type — reuse a ChatGPT prompt inside Claude |
| **Dashboard** | Activity by day/week/month, tool breakdown, search, filters |
| **Export** | Full history as JSON |
| **Optional sync** | Cloudflare Worker or GitHub Gist — both disabled by default |

---

## 5 · Deployment

### Install in Chrome

**1.** Download or clone this repository.

**2.** Open **`chrome://extensions`**

**3.** Enable **Developer mode** (top-right toggle)

**4.** Click **Load unpacked**

**5.** Select the **folder containing `manifest.json`** — the top level of the downloaded project.

> Pick the level where `manifest.json` sits — not your `Downloads` folder, and not the
> `extension/` subfolder. Chrome also rejects any extension directory containing a name
> beginning with `_` (a stray `__pycache__`, for example), reporting a misleading
> *"Could not load manifest"*.

**6.** Pin it — click the puzzle icon in the toolbar and pin **Promptrix**.

### After changing any file

Press **Reload** on the Promptrix card at `chrome://extensions`, then hard-reload any open
dashboard tab with **⌘⇧R** / **Ctrl+Shift+R**. Chrome caches extension pages aggressively.

### First run

1. Send a prompt on any supported site — capture and DLP are active immediately.
2. Click the Promptrix icon → **Dashboard**.
3. Open **DLP** to review the detector matrix, content inspection and activity log.

All policy and settings changes **save automatically** — there is no Save step.

---

## 6 · Specifications

| Item | Value |
|---|---|
| Manifest version | 3 |
| Product version | 7.0.0 |
| Detectors | 224 (165 default-on) |
| Detector actions | 4 per detector, independently set |
| Classifications | 5 |
| Checksum validators | Verhoeff · Luhn · IBAN MOD-97 |
| File signatures | 14 |
| Max inspected file | 4 MB (configurable) |
| SIEM formats / auth / events | 8 / 6 / 7 |
| Event spool | 500 events |
| Local retention | Byte-budgeted, 4 MB capture store |

### Permissions

| Permission | Purpose |
|---|---|
| `storage`, `unlimitedStorage` | Local prompt history and policy |
| `webNavigation` | Resolve the permanent conversation URL |
| `clipboardRead`, `clipboardWrite` | Copy prompts; paste masked text where an editor rejects direct writes |
| `alarms` | Scheduled SIEM spool flush |
| `optional_host_permissions` | Requested **only** when a SIEM or sync endpoint is configured |

---

## 7 · Privacy & data handling

**Detection is entirely on-device.** The DLP engine makes no network requests. Prompts are
scanned locally and masked before they reach the AI provider.

Three features transmit data, and **all three are disabled until you configure them**:

| Feature | Destination | Default |
|---|---|---|
| Cloudflare Sync | Your own Worker | **Disabled** |
| GitHub Gist backup | Your private Gist | **Disabled** |
| SIEM forwarding | Your collector | **Disabled** · metadata-only when enabled |

Audit logs record **redacted evidence only** — raw secret values are never written to disk.

---

## Supported platforms

| AI tool | Prompt capture | Response capture | DLP masking | File inspection |
|---|:---:|:---:|:---:|:---:|
| ChatGPT | ✅ | ✅ | ✅ | ✅ |
| Gemini | ✅ | ✅ | ✅ | ✅ |
| Claude | ✅ | ✅ | ✅ | ✅ |
| Perplexity | ✅ | ✅ | ✅ | ✅ |
| Copilot | ✅ | ✅ | ✅ | ✅ |

---

*Inspired by Zscaler GenAI DLP · Supermemory.ai*

**Promptrix 7.0.0 — Manifest V3**
