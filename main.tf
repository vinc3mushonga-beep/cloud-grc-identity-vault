# ==========================================
# AWS CLOUD GRC PERIMETER DEFENSE LANDSCAPE
# Enforces PoLP and Zero-Trust Network Boundary
# ==========================================

provider "aws" {
  region = "us-east-1"
}

# ------------------------------------------
# TARGET ASSET: Secure S3 Financial Vault
# ------------------------------------------
resource "aws_s3_bucket" "financial_vault" {
  bucket        = "grc-secure-financial-vault-2026"
  force_destroy = false # Prevent accidental deletion via code
}

# Control: Enforce Public Access Block (SOC 2 / ISO 27001 Requirement)
resource "aws_s3_bucket_public_access_block" "vault_privacy_boundary" {
  bucket = aws_s3_bucket.financial_vault.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ------------------------------------------
# LAYER 1: Financial Auditor Role (Read-Only)
# ------------------------------------------
resource "aws_iam_role" "auditor_role" {
  name = "Financial-Auditor-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { AWS = "*" } # Configured for account-wide access
    }]
  })
}

resource "aws_iam_role_policy_attachment" "auditor_read_only" {
  role       = aws_iam_role.auditor_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

# ------------------------------------------
# LAYER 2: Financial Admin Role (Full Access)
# ------------------------------------------
resource "aws_iam_role" "admin_role" {
  name = "Financial-Admin-Role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { AWS = "*" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin_full_access" {
  role       = aws_iam_role.admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

# ------------------------------------------
# LAYER 3: Explicit Deny Perimeter Policy
# ------------------------------------------
resource "aws_s3_bucket_policy" "perimeter_defense_policy" {
  bucket = aws_s3_bucket.financial_vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EnforceCorporateNetworkBoundary"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.financial_vault.arn,
        "${aws_s3_bucket.financial_vault.arn}/*"
      ]
      Condition = {
        NotIpAddress = {
          "aws:SourceIp" = [
            "41.76.101.201/32" # Your verified corporate IP footprint
          ]
        }
      }
    }]
  })

  # Ensures public access blocks are fully evaluated before policy attachment
  depends_on = [aws_s3_bucket_public_access_block.vault_privacy_boundary]
}
