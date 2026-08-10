# AWS Cloud GRC: Three-Layered Identity & Network Perimeter Defense for Sensitive Data

## 📌 Project Overview
This project implements a production-grade Cloud Governance, Risk, and Compliance (GRC) security framework around a sensitive AWS S3 data asset (`grc-secure-financial-vault-2026`). 

In an enterprise environment, high-level corporate risk metrics must translate into un-bypassable cloud security controls. This project applies the **Principle of Least Privilege (PoLP)** and zero-trust network architectural concepts to defend sensitive data against credential theft and unauthorized manipulation.

## 📂 Repository Structure

```text
├── policies/
│   ├── s3-perimeter-bucket-policy.json     # Layer 3 Enforced Network Boundary
│   └── financial-admin-trust-policy.json   # IAM Role Trust Relationship Definition
├── img/
│   ├── auditor-delete-denied.png           # Visual Proof: Integrity Verification
│   └── external-ip-admin-denied.png        # Visual Proof: Perimeter Verification
├── main.tf                                 # Infrastructure-as-Code (Compliance as Code)
└── README.md                               # GRC Control Framework & Audit Trail Logs
```



## 🛡️ Control Architecture (The 3 Layers)
The architecture establishes three distinct layers of identity and network boundaries:
1. **Layer 1: The Auditor Role (Read-Only Control)** – Grants necessary access to inspect compliance without risking data integrity (Confidentiality).
2. **Layer 2: The Admin Role (Management Control)** – Provides structural capabilities to manage lifecycle rules and bucket configurations to authorized engineers (Availability).
3. **Layer 3: Explicit Deny Policy (Network Perimeter Control)** – A global safeguard overriding all permissions. Even if administrative credentials are stolen, data access is blocked unless the request originates from the company's secure network IP space.

---

## 🗺️ GRC Framework Mapping

| Control ID | Risk Metric | Technical Control Implemented | CIA Triad | Impact |
| :--- | :--- | :--- | :--- | :--- |
| **FIN-S3-01** | Unauthorized Data Exfiltration | `Financial-Auditor-Role` with `AmazonS3ReadOnlyAccess` | Confidentiality | **Mitigated** |
| **FIN-S3-02** | Accidental/Malicious Deletion | Multi-layer write restriction + IAM boundary block | Integrity | **Mitigated** |
| **FIN-S3-03** | Credential Theft / Perimeter Breach | S3 Bucket Policy with `Explicit Deny` on `NotIpAddress` | Perimeter Defense | **Mitigated** |

---

## 🛠️ Step-by-Step Implementation Guide

### Step 1: Establish the Target Asset
1. Navigated to the **Amazon S3 Console** and created a uniquely named bucket: `grc-secure-financial-vault-2026`.
2. Enforced strict compliance by keeping **Block Public Access** fully enabled to eliminate accidental exposure.

### Step 2: Configure Layer 1 (The Auditor Role)
1. Created an IAM Role named `Financial-Auditor-Role` using the local AWS account as the trusted entity.
2. Attached the AWS-managed policy `AmazonS3ReadOnlyAccess`.
3. *Result:* Users assuming this role can read logs and verify configurations but cannot delete or overwrite evidence.

### Step 3: Configure Layer 2 (The Admin Role)
1. Created an IAM Role named `Financial-Admin-Role` using the local AWS account as the trusted entity.
2. Attached the AWS-managed policy `AmazonS3FullAccess` to permit structural management.

### Step 4: Enforce Layer 3 (The Hard Network Boundary)
1. Navigated to the S3 bucket permissions tab and deployed the following **Bucket Policy**. 
2. This policy utilizes a `Deny` effect tied to a `NotIpAddress` condition block to isolate data access exclusively to corporate CIDR ranges.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceCorporateNetworkBoundary",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::grc-secure-financial-vault-2026",
        "arn:aws:s3:::grc-secure-financial-vault-2026/*"
      ],
      "Condition": {
        "NotIpAddress": {
          "aws:SourceIp": [
            "192.0.2.0/24"
          ]
        }
      }
    }
  ]
}
```

---

## 🧪 Control Validation & Empirical Evidence
To verify operational effectiveness, compliance tests were executed across all access vectors.

### Validation Test Log

| Test ID | Assumed Identity | Source IP Address | Attempted Action | Expected GRC Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TST-01** | `Financial-Auditor-Role` | Approved Corp IP | Read Object | **Allowed** | **Allowed** | **PASS** |
| **TST-02** | `Financial-Auditor-Role` | Approved Corp IP | Delete Object | **Denied** | **Access Denied** | **PASS** |
| **TST-03** | `Financial-Admin-Role` | Approved Corp IP | Put/Write Object | **Allowed** | **Allowed** | **PASS** |
| **TST-04** | `Financial-Admin-Role` | Untrusted External IP | List/Read Bucket | **Denied** | **Access Denied** | **PASS** |

### Immutable Audit Trail (AWS CloudTrail JSON)
Below is an exported snippet from AWS CloudTrail verifying that the AWS Policy Engine successfully intercepted and dropped an administrative request because it breached the defined network boundary (**TST-04**):

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:iam::123456789012:assumed-role/Financial-Admin-Role/Auditor-Test",
    "sessionContext": {
      "sessionIssuer": { "userName": "Financial-Admin-Role" }
    }
  },
  "eventTime": "2026-08-10T14:30:00Z",
  "eventSource": "://amazonaws.com",
  "eventName": "ListObjects",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.12",
  "errorCode": "AccessDenied",
  "errorMessage": "Access Denied"
}
```

## 🚀 Key Takeaways & Competencies Demonstrated
* **Zero-Trust Network Architecture**: Demonstrated how to treat credentials as insufficient for authorization without matching network conditions.
* **AWS Identity and Access Management (IAM)**: Mastered context-aware evaluations, trust policies, and explicit deny logic.
* **Audit Readiness**: Created verifiable audit logs matching standard SOC 2 and ISO 27001 evidence requests.
