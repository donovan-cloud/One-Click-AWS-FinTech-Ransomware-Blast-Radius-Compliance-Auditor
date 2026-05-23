# AWS FinTech Storage Plane & Identity Infrastructure Security Auditor

1. Project Architectural Overview

This repository contains an enterprise-grade, zero-data-retention security assessment engine designed for rapid deployment within highly regulated Financial Technology environments. Operating with localized administrative scope natively inside the AWS CloudShell environment, this framework programmatically maps account-wide data exposure vulnerabilities, evaluates storage architectures against destructive ransomware configurations, isolates identity privilege escalation vectors, and flags critical compliance defects—delivering a comprehensive risk landscape synthesis in under 60 seconds.

2. Technical Audit Vectors & Risk Mapping

The assessment engine performs deep-plane metadata inspection across three primary high-severity threat vectors:

2.1 Storage Layer Resiliency & WORM Immutability Audit
Telemetry Targets: Programmatically queries all Amazon S3 resource buckets specifically evaluating the active states of S3 Bucket Versioning and S3 Object Lock configuration metadata.

Adversary Risk Vector: Storage environments operating without rigid data immutability constraints allow compromised credentials or application-layer flaws to execute destructive object overwrites or malicious bulk encryption. This completely eliminates the organization's native point-in-time recovery capabilities during an active ransomware extortion event.

2.2 Identity Plane Blast Radius & Privilege Escalation Analysis

Telemetry Targets: Interrogates the AWS IAM infrastructure layer to isolate active, system-facing service roles directly bound to the global AdministratorAccess managed policy footprint.

Adversary Risk Vector: Attaching un-scoped administrative capabilities to application or compute environments, such as AWS Lambda functions or Amazon EC2 instances, presents a critical lateral-movement target. An attacker achieving Remote Code Execution via the application runtime can instantly hijack the host role to compromise the entire cloud organization.

2.3 Storage Cryptographic Rotation & Compliance Audit

Telemetry Targets: Evaluates account-level Customer Managed Keys within the AWS Key Management Service to isolate active cryptographic keys running with automated annual rotation variables set to a false value.

Adversary Risk Vector: Prolonged cryptographic key lifecycles increase the statistical feasibility of historical data decryption upon credential compromise, violating foundational compliance mandates concerning financial data-at-rest protection.

3. Script Logic & Structural Execution

The execution trace runs sequentially via an executable Shell script. The program flow functions through the following logical progression:

Initialization Phase: Environmental terminal text colors are mapped using standard ANSI escape sequences. Red represents critical system vulnerabilities, yellow indicates active processing tasks, blue designates header wrappers, and green marks fully compliant infrastructures.

Storage Plane Loop: The engine executes an API listing query against the S3 service resource plane. For each detected unique bucket identifier, consecutive API calls are dispatched to fetch the bucket versioning status and object lock configuration. If either check fails to return an enabled flag, a high-risk defect warning is printed to stdout.

Identity Plane Query: The script targets the IAM API layer, filtering entities explicitly attached to the Amazon Resource Name for the global root-level administrator policy. Any service roles detected within this array are flagged as critical security defects.

Cryptographic Keys Validation: A master list of account-level Key Identifiers is requested from the KMS API. The script iterates through each key string, querying the rotation boolean status. Keys returning a false state are flagged as non-compliant.

4. Professional Retainer Remediation & Deliverables Blueprint

The technical vulnerabilities identified by this script serve as the direct foundational input for a structured, continuous SecOps architecture retainer. Remediation pipelines are mapped into three precise engineering phases:

Identity Architecture Hardening: Eradicating un-scoped AWS-managed policies from application contexts and engineering surgical, customer-managed inline IAM policies restricted to exact programmatic system calls.

Immutability Controls Enforcement: Provisioning definitive infrastructure-as-code configurations using Terraform modules to enforce S3 Object Lock compliance, legal hold parameters, and multi-factor authentication delete mechanics across all core transactional persistence layers.

Continuous Compliance Guardrails: Designing and deploying custom AWS Config rules to actively monitor resource state changes, mapping configuration drift in real time to satisfy PCI-DSS v4.0.1 Requirement 3 and Requirement 7 alongside SOC 2 Type II Identity Governance frameworks.
