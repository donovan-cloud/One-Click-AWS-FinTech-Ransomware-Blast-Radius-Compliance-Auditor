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
