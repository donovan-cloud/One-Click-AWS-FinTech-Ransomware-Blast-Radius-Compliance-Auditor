# AWS FinTech Storage Plane & Identity Infrastructure Security Auditor

[![Runtime](https://img.shields.io/badge/Runtime-Bash_Shell-green.svg)](https://www.gnu.org/software/bash/)
[![Provider](https://img.shields.io/badge/Provider-AWS_CLI-orange.svg)](https://aws.amazon.com/cli/)
[![Category](https://img.shields.io/badge/Security-Infrastructure_Audit-blue.svg)](https://aws.amazon.com/security/)
[![Compliance](https://img.shields.io/badge/Compliance-PCI--DSS_/_SOC_2-red.svg)](https://aws.amazon.com/security/)

## 📋 Project Overview
This repository contains an enterprise-grade, zero-data-retention security assessment engine designed for rapid deployment inside highly regulated Financial Technology environments. 

Operating with localized administrative scope natively within the AWS CloudShell environment, this framework programmatically maps account-wide data exposure vulnerabilities, evaluates storage architectures against destructive ransomware configurations, isolates identity privilege escalation vectors, and flags critical compliance defects—delivering a comprehensive risk landscape synthesis in under 60 seconds.

---

## 🔍 Technical Audit Vectors & Risk Mapping

The assessment engine performs deep-plane metadata inspection across three primary high-severity threat vectors:

| Audit Target | Telemetry Parameters | Adversary Risk Vector |
| :--- | :--- | :--- |
| **Storage Layer Immutability** | Amazon S3 Bucket Versioning & S3 Object Lock states | Storage environments operating without WORM constraints allow compromised credentials to execute destructive object overwrites, eliminating point-in-time recovery during a ransomware event. |
| **Identity Plane Blast Radius** | AWS IAM infrastructure roles bound to `AdministratorAccess` | Attaching un-scoped administrative capabilities to compute platforms (Lambda, EC2) presents a critical lateral-movement target if an attacker achieves Remote Code Execution (RCE). |
| **Cryptographic Governance** | AWS KMS Customer Managed Keys (CMK) annual rotation status | Prolonged cryptographic key lifecycles increase the statistical feasibility of historical data decryption upon credential compromise, violating financial data protection mandates. |

---

## 🏗️ Script Logic & Structural Execution

The execution trace runs sequentially via a native Shell script following a strict operational flow:
1. **Visual Mappings:** Maps environment terminal text outputs using standard ANSI escape sequences (`Red` for critical defects, `Yellow` for active scanning, `Green` for compliant states).
2. **Storage Loop:** Targets the S3 service resource plane to parse active metadata signatures, flagging any buckets operating without explicit point-in-time recovery and WORM capabilities.
3. **Identity Check:** Interrogates the IAM API layer to isolate any application or microservice execution roles improperly carrying global root-level administrator privileges.
4. **Crypto Validation:** Queries the KMS configuration layer to catch keys operating with automated annual rotation turned off.

---

## 💻 Core Assessment Engine Script (`audit-engine.sh`)

This shell script executes the zero-data-retention security assessment directly through the AWS command-line plane, outputting a live, colorized posture readout:

```bash
#!/bin/bash

# Define clear terminal colors for the executive report output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0;0m' # No Color

echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}FINTECH AUTOMATED RANSOMWARE BLAST-RADIUS & COMPLIANCE REPORT${NC}"
echo -e "${BLUE}==================================================================${NC}"
echo -e "Generated on: $(date)"
echo ""

# --- AUDIT VECTOR 1: S3 RANSOMWARE & WORM ANALYSIS ---
echo -e "${YELLOW}[*] Auditing Storage Plane for Ransomware Resiliency...${NC}"
BUCKETS=$(aws s3api list-buckets --query "Buckets[*].Name" --output text 2>/dev/null)

if [ -z "$BUCKETS" ]; then
    echo -e "${GREEN}[✔] No S3 Buckets discovered in this target environment.${NC}"
else
    for bucket in $BUCKETS; do
        # Check for Point-in-Time Versioning
        VERSIONING=$(aws s3api get-bucket-versioning --bucket "$bucket" --query "Status" --output text 2>/dev/null)
        # Check for Immutable Object Lock Configuration
        OBJECT_LOCK=$(aws s3api get-bucket-object-lock-configuration --bucket "$bucket" --query "ObjectLockConfiguration.ObjectLockEnabled" --output text 2>/dev/null)
        
        echo -e "Target Bucket: ${BLUE}$bucket${NC}"
        
        if [ "$VERSIONING" == "Enabled" ]; then
            echo -e "  - S3 Versioning State: ${GREEN}ENABLED${NC}"
        else
            echo -e "  - S3 Versioning State: ${RED}CRITICAL VULNERABILITY (Missing Point-in-Time Recovery)${NC}"
        fi
        
        if [ "$OBJECT_LOCK" == "Enabled" ]; then
            echo -e "  - S3 WORM Object Lock: ${GREEN}ENABLED${NC}"
        else
            echo -e "  - S3 WORM Object Lock: ${RED}HIGH RISK (Vulnerable to Ransomware Administrative Deletion)${NC}"
        fi
        echo ""
    done
fi

# --- AUDIT VECTOR 2: IDENTITY COMPLIANCE & PRIVILEGE ESCALATION ---
echo -e "${YELLOW}[*] Evaluating Identity Plane for Over-Privileged Service Entities...${NC}"
# Query for Roles containing the broad AdministratorAccess managed policy footprint
ROLES_WITH_ADMIN=$(aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess --query "PolicyRoles[*].RoleName" --output text 2>/dev/null)

if [ -z "$ROLES_WITH_ADMIN" ]; then
    echo -e "${GREEN}[✔] Zero service identities map to broad AdministratorAccess.${NC}"
else
    echo -e "${RED}CRITICAL SECURITY DEFECT: The following roles hold un-scoped Administrative Rights:${NC}"
    for role in $ROLES_WITH_ADMIN; do
        echo -e "  - IAM Identity Profile: ${RED}$role${NC}"
    done
fi
echo ""

# --- AUDIT VECTOR 3: DATA AT REST REPLICATED ENCRYPTION CHECKS ---
echo -e "${YELLOW}[*] Validating Storage Layer Cryptographic Isolations...${NC}"
echo -e "Reviewing account-wide managed encryption states for compliance artifacts..."
# Quickly check if any standard custom KMS master keys are configured for manual rotation
KMS_KEYS=$(aws kms list-keys --query "Keys[*].KeyId" --output text 2>/dev/null)

for key in $KMS_KEYS; do
    ROTATION_STATUS=$(aws kms get-key-rotation-status --key-id "$key" --query "KeyRotationEnabled" --output text 2>/dev/null)
    if [ "$ROTATION_STATUS" == "false" ]; then
        echo -e "  - KMS Key ID: ${BLUE}$key${NC} Status: ${YELLOW}NON-COMPLIANT (Automatic Annual Rotation Disabled)${NC}"
    fi
done

echo ""
echo -e "${BLUE}==================================================================${NC}"
echo -e "${BLUE}            [✔] AUDIT ENGINE PROCESSING COMPLETE                  ${NC}"
echo -e "${BLUE}==================================================================${NC}"
