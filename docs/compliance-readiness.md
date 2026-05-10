# Compliance Readiness

This is an engineering readiness packet, not a certification or legal opinion. Use counsel and an independent auditor for formal SOC 2, GDPR/DPA, and HIPAA/BAA commitments.

## Evidence Map

| Program | AuthService evidence |
|---|---|
| SOC 2 readiness | Audit exports, hash-chain verification, metrics, backup/restore drills, access reviews, secret rotation records, incident runbooks, deployment change logs. |
| GDPR/DPA readiness | Tenant-scoped data model, exportable audit evidence, configurable retention, legal hold, deletion/purge procedures, subprocessor register, documented controller/processor responsibilities. |
| HIPAA/BAA readiness | Encryption and access-control deployment requirements, audit logging, backup/restore RPO/RTO, incident procedures, subcontractor/BAA tracking, minimum necessary configuration guidance. |

## SOC 2 Readiness

SOC 2 reports evaluate controls relevant to security, availability, processing integrity, confidentiality, or privacy. AuthService supports evidence collection for those areas but does not replace company-level controls such as HR background checks, vendor risk management, change approval, endpoint management, or security awareness training.

Evidence to collect for a review:

| Area | Evidence source |
|---|---|
| Security | Admin access review, `GET /api/admin/audit-events/export`, legal-hold records, token reuse alerts, SIEM stream health. |
| Availability | `/healthz`, `/metrics`, uptime monitor, backup job history, restore drill RPO/RTO record. |
| Processing integrity | Migration logs, deployment approvals, audit chain verification, webhook delivery metrics. |
| Confidentiality | Secret manager inventory, database encryption proof, TLS configuration, restricted metrics/audit access. |
| Privacy | Retention policy, purge logs, DPA subprocessors, data subject request procedure. |

## GDPR And DPA Readiness

For hosted mode, document whether AuthService acts as a processor for customer-controlled identity data. A DPA should define processing purposes, categories of personal data, retention, security measures, breach notice, assistance with data subject requests, deletion/return at termination, and subprocessor authorization. GDPR Article 28 processor obligations are the reference model for this section.

Operational controls:

1. Keep `AUDIT_RETENTION_DAYS` aligned with customer contracts and privacy notices.
2. Use legal hold only for documented legal/security reasons.
3. Export tenant data from PostgreSQL with read-only credentials and rotate secrets in the target environment.
4. Run retention purge only after confirming no legal hold and no active evidence request.
5. Maintain a current subprocessor list and customer notice process.

## HIPAA And BAA Readiness

Only offer a BAA for hosted mode after confirming the deployment, support, logging, backup, and subprocessor controls are in scope. HHS guidance expects business associate contracts to define permitted PHI use/disclosure, safeguards, breach reporting, downstream subcontractor obligations, access/accounting support, and return or destruction at termination.

Minimum hosted-mode controls before signing a BAA:

| Control | Required evidence |
|---|---|
| Access control | Named admin identities, MFA, least-privilege roles, quarterly access review. |
| Audit control | Audit exports with event hashes, SIEM delivery, immutable/durable log retention. |
| Integrity | Hash-chain verification, migration/change approvals, backup checksums. |
| Transmission security | TLS-only endpoints, secure cookies in production, restricted admin/metrics ingress. |
| Contingency | Tested restore drill with RPO/RTO, regional failover runbook. |
| Subcontractors | BAA/DPA status for hosting, email, logging, support, and monitoring vendors. |

## Hosted-Mode Subprocessor Register

Self-hosted customers control their own subprocessors. Hosted mode must publish and maintain this register.

| Subprocessor | Purpose | Data categories | Regions | Contract status |
|---|---|---|---|---|
| Hosting provider | Compute, database, Redis, backups | Identity profile, credentials hashes, sessions, audit events | `<regions>` | DPA/BAA as applicable |
| Email provider, such as Resend | Verification, password reset, magic-link email | Email address, template metadata | `<regions>` | DPA required; BAA if PHI use is allowed |
| SIEM/logging provider | Audit/security log processing | Audit events, IP, user agent, admin actor metadata | `<regions>` | DPA required; BAA if in HIPAA scope |
| Monitoring/on-call provider | Metrics, alerts, incident response | Metrics, service metadata | `<regions>` | DPA as applicable |
| Support tooling | Customer support and incident work | Customer contact data, limited tenant metadata | `<regions>` | DPA required |

## Customer Evidence Packet

For a security review, provide:

1. `docs/operations-runbook.md` with latest restore drill RPO/RTO.
2. `docs/multi-region-deployment.md` for deployment and JWKS cache posture.
3. CSV or NDJSON audit export for the requested period.
4. Chain verification response for the same tenant/period.
5. Metrics screenshot or scrape excerpt for login failures, MFA challenges, SSO errors, SCIM lag, webhook delivery, token refresh reuse, and latency.
6. Current subprocessor register and DPA/BAA status.
7. Incident response and breach notification contacts.

References: [AICPA SOC 2 Trust Services Criteria](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2), [GDPR Article 28](https://www.edpb.europa.eu/gdpr-articles/article-28-processor_en), and [HHS business associate contracts](https://www.hhs.gov/hipaa/for-professionals/covered-entities/sample-business-associate-agreement-provisions).
