# Classification definitions and decision rules

## Primary attack surface

Assign one surface describing the exposed operation or resource that explains the initial failure.

| Category | Definition | Example |
| --- | --- | --- |
| Network | Communication and network-access boundaries, including WebSocket handling, server-side request forgery, isolation bypass, and network denial of service. | OpenClaw GHSA-G8P2-7WF7-98MQ: 1-Click RCE via Authentication Token Exfiltration From gatewayUrl |
| Authentication & Authorization | Identity checks, credential handling, and enforcement of roles and access scopes. | OpenClaw GHSA-4RJ2-GPMH-QQ5X: Inbound allowlist policy bypass in voice-call extension (empty caller ID + suffix matching) |
| Code Execution | Command interpretation, executable selection, and enforcement of execution policies. | OpenClaw GHSA-MC68-Q9JW-2H3V: Command Injection in Clawdbot Docker Execution via PATH Environment Variable |
| File System | Path containment and unauthorized access to or modification of files and file metadata. | OpenClaw GHSA-66R7-M7XM-V49H: QQBot media tags could read arbitrary local files through reply text |
| Supply Chain | Untrusted extensions, their loading or installation, and vulnerable dependencies. | OpenClaw GHSA-QCJ9-WWGW-6GM8: Workspace `.env` can override the bundled plugin trust root |
| Client-Side | Browser, application, deep-link, and terminal interaction boundaries. | OpenClaw GHSA-HR8G-2Q7X-3F4W: OpenClaw Gateway Control Interface Information Disclosure Vulnerability |
| Context Manipulation | Untrusted instructions or state affecting the model's context, interpretation, or later behavior. | OpenClaw GHSA-782P-5FR5-7FJ8: Slack integration hardening: prevent channel metadata from influencing system prompts |

## Primary root cause

Assign one root cause describing the deficient control that explains the initial failure. Distinguish validation from authorization by the deficient control: malformed identity-value handling can be a validation failure, while omitting a target-scope check is an authorization failure.

| Category | Definition | Example |
| --- | --- | --- |
| Missing validation | Deficient checks on supplied values, their comparison, or resolved destinations. | OpenClaw GHSA-4RJ2-GPMH-QQ5X: Inbound allowlist policy bypass in voice-call extension (empty caller ID + suffix matching) |
| Insufficient authentication/authorization | A missing or inadequate decision about who may invoke an operation or access its target. | OpenClaw GHSA-WCXR-59V9-RXR8: `session_status` let sandboxed subagents access parent or sibling session state |
| Logic error | Faulty normalization, ordering, or races. | OpenClaw GHSA-Q99W-VH6V-Q3V7: Pairing-scoped device session could restore revoked node token authority |
| Insecure defaults | Unsafe default configuration. | OpenClaw GHSA-943Q-MWMV-HHVH: OC-02: Gateway /tools/invoke tool escalation + ACP permission auto-approval |
| Design flaw | An unsafe protocol or workflow. | OpenClaw GHSA-GV46-4XFQ-JV58: Client-supplied approval fields bypass node execution approval |
| Information disclosure | Direct unintended exposure, such as sensitive logging. | OpenClaw GHSA-HR8G-2Q7X-3F4W: OpenClaw Gateway Control Interface Information Disclosure Vulnerability |
| Dependency defect | A weakness in an external component. | OpenClaw 93421: security-fast reports high-or-higher production dependency advisories |
| Context trust failure | Accepting untrusted material as instructions. | OpenClaw GHSA-782P-5FR5-7FJ8: Slack channel metadata incorporated into the system prompt |

## Attack stage and exploitation prerequisite

Attack stage describes the attacker's action through the vulnerable operation, rather than the failed control. The six stages are Initial Access, Context Manipulation, Execution, Credential Access, Privilege Escalation, and Impact.

Record the required access separately as unauthenticated remote access, authenticated access, local access, or complex conditions such as a race or multi-step chain.

## Lifecycle location

Assign the location of the failed operation in framework processing, independently of attack stage. Use Unknown when the source does not establish a usable location.

| Category | Definition | Example |
| --- | --- | --- |
| P0 | Supply/environment setup. | OpenClaw GHSA-QCJ9-WWGW-6GM8: Workspace `.env` can override the bundled plugin trust root |
| P1 | Input adaptation. | OpenClaw GHSA-Q447-RJ3R-2CGH: Denial of service via unbounded webhook request body buffering |
| P2 | Gateway authentication/routing. | OpenClaw GHSA-4RJ2-GPMH-QQ5X: Inbound allowlist policy bypass in voice-call extension (empty caller ID + suffix matching) |
| P3 | Agent runtime. | OpenClaw GHSA-V3QC-WRWX-J3PW: Agentic Consent Bypass: LLM Agent Can Silently Disable Exec Approval via `config.patch` |
| P4 | Tool execution. | OpenClaw GHSA-WCXR-59V9-RXR8: `session_status` let sandboxed subagents access parent or sibling session state |
| P5 | Output/persistence. | OpenClaw GHSA-66R7-M7XM-V49H: QQBot media tags could read arbitrary local files through reply text |

## Propagation patterns and forms

Include a trace-supported case when sources establish the operation, receiving component, and failed security requirement. Same-layer handoffs and reuse in later tasks can qualify. For A–G, assign one primary pattern according to the principal failed security requirement and the control that addresses it. If one failure enables another, select the upstream failure. H and I are separate from A–G.

| Category | Definition | Example |
| --- | --- | --- |
| A. False authorization claims | The source of authority is not verified. | OpenClaw GHSA-GV46-4XFQ-JV58: Client-supplied approval fields bypass node execution approval |
| B. Check–use mismatch | The checked object differs from the object used. | OpenClaw GHSA-2J8V-HWGC-X698: Shell wrapper argv could change between approval and execution |
| C. Security context loss | Context is lost or incorrectly changed. | OpenClaw GHSA-P7GR-F84W-HQG5: Sandboxed sessions_spawn now enforces sandbox inheritance for cross-agent spawns |
| D. Execution-flow hijacking | Untrusted configuration selects code. | OpenClaw GHSA-JQPQ-MGVM-F9R6: Command hijacking via unsafe PATH handling (bootstrapping + node-host PATH overrides) |
| E. Data treated as trusted instructions | Data gains trusted instruction status. | OpenClaw GHSA-782P-5FR5-7FJ8: Slack integration hardening: prevent channel metadata from influencing system prompts |
| F. Input authorization bypass | New input skips source and activation checks. | OpenClaw GHSA-792Q-QW95-F446: Signal reaction-only status events could, in limited cases, be enqueued before access checks |
| G. Unintended credential transmission | A credential reaches an unintended recipient. | OpenClaw GHSA-G8P2-7WF7-98MQ: 1-Click RCE via Authentication Token Exfiltration From gatewayUrl |
| H. Automatically triggered resource delivery | A returned reference leads to resource delivery. | OpenClaw GHSA-66R7-M7XM-V49H: QQBot media tags could read arbitrary local files through reply text |
| I. Stored content reused across tasks | Stored content reaches a later task. | OpenClaw GHSA-62QM-6FJJ-6G23: Dreaming could widen restricted sender authority |

## Repair status and mechanisms

Code whether the source reports an implemented change, proposes a change, leaves adoption unclear, or supplies no repair evidence. Implementation means a source-reported or patch-observed change, not verified effectiveness. Issue closure alone does not establish implementation. A patched-version statement can establish a reported repair without identifying its mechanism. Keep conflicting adoption claims as unclear. When a compatibility change is established but a security-repair mechanism is not, retain the record and mark the mechanism Unknown.

Assign mechanisms according to the concrete control changed. A repair may receive multiple distinct mechanism labels. Exclude proposals and unclear adoption from implemented-mechanism counts.

| Mechanism | Changed control | Example |
| --- | --- | --- |
| Caller and origin authentication | Verify request identity, signatures, or trusted origin. | OpenClaw GHSA-25GX-X37C-7PPH: Sandbox browser noVNC observer lacked VNC authentication |
| Actor–action authorization | Check permission for the requested action or object. | Hermes 38068: Slack approval and confirmation buttons ignored configured authorization |
| Principal and session binding | Resolve state and authority for the correct identity or session. | Hermes 113270: Profile-scoped authorization gates leak across profiles: spawned `hermes` children inherit the spawning profile's `DISCORD_*` / `TELEGRAM_*` / `SLACK_*` / `GATEWAY_ALLOW*` gates |
| Explicit approval gates | Require consent before a privileged operation. | Hermes 20733: [Bug]: approval.py silently fails open on Tirith ImportError, ignoring tirith_fail_open: false |
| Capability and delegation limits | Restrict available or inherited tools and capabilities. | Hermes 43466: delegate_task: _strip_blocked_tools doesn't strip 'messaging'/'cronjob', so children inherit send_message and cronjob despite DELEGATE_BLOCKED_TOOLS |
| Approval–operation binding | Keep approved details identical to the executed operation. | OpenClaw GHSA-2CQ5-MF3V-MX44: busybox and toybox applet execution weakened exec approval binding |
| File-target confinement | Resolve and constrain local reads or writes to allowed targets. | Hermes 108346: [Bug]: profile param on gateway RPCs resolves traversal-shaped names as filesystem paths |
| Network-target confinement | Check schemes, hosts, addresses, and redirect destinations. | Hermes 11345: Discord: document-attachment downloads bypass the SSRF `is_safe_url` guard |
| Process deprivileging | Filter inherited authority or isolate the execution environment. | Hermes 37258: fix(browser): scrub credentials from browser subprocess env |
| Configuration trust | Block lower-trust sources from changing security settings. | Hermes 85050: Plugin packs allow nested secrets and capability grants in config seeds |
| Parser-safe construction | Keep untrusted values as data in an interpreter or renderer. | Hermes 71296: [Bug]: Newline in a Matrix room/display name runs shell commands on the gateway host |
| Configuration–cache binding | Preserve the identity of effective sandbox configuration. | OpenClaw GHSA-FH3F-Q9QW-93J9: Replace deprecated sandbox hash algorithm |
| Content provenance and framing | Preserve lower-trust source and instruction status. | Hermes 111564: Group chat: agent output containing the literal [OUT-OF-BAND USER MESSAGE] marker is treated as a genuine user message by every participant |
| Content inspection and suppression | Scan, reject, or remove hostile instruction-bearing content. | Hermes 3968: Security: Cron prompt injection via skill content bypasses scanner |
| Credential storage and selection | Use protected storage or the intended credential source. | Hermes 121932: Remote execute_code drops the RPC token and tool data in world/group-accessible paths on shared backends |
| Output minimization and redaction | Omit or mask sensitive content before disclosure. | Hermes 109362: redact_terminal_output: secrets leak when the command reads config.yaml or shell rc files (code_file gate skips the assignment passes) |
| Stored-data access and retention | Restrict access to persisted data or unnecessary retention. | Hermes 121932: Remote execute_code drops the RPC token and tool data in world/group-accessible paths on shared backends |
| Per-operation resource budgets | Bound the size, duration, or work of one operation. | Hermes 12543: webhook: max_body_bytes check is bypassed for chunked requests without Content-Length |
| Rate and concurrency controls | Bound repeated attempts or concurrent admission. | OpenClaw GHSA-5847-RM3G-23MW: Hook auth rate limiter bypass via IPv4-mapped IPv6 client key variants |
| Freshness and replay controls | Reject stale, duplicated, or already-consumed requests. | OpenClaw GHSA-8689-GM9G-JGR6: Plivo webhook replay via reordered query parameters |
| Fault containment | Keep one failed operation from disabling unrelated work. | Hermes 36854: Cron ticker silently dies when prompt-injection scanner blocks a job — entire cron scheduler stops until gateway restart |
| Vulnerable-component remediation | Replace, remove, or constrain a vulnerable dependency. | Hermes 10695: Python dependency CVEs: aiohttp, cryptography, curl-cffi need minimum version bumps |
| Executable provenance and integrity | Verify or restrict the origin and identity of executable artifacts. | Hermes 38017: fix(mcp): pin optional catalog installs before bootstrap |
| Security posture auditing | Detect unsafe settings or scan coverage and report the risk. | OpenClaw 139494: [Bug]: gateway.auth.token literal "undefined" is accepted silently; doctor and security audit do not flag it |
