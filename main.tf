terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Konfigurasi agar Terraform mengirim perintah ke LocalStack (bukan AWS asli)
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  s3_use_path_style           = true

  endpoints {
    s3  = "http://localhost:4566"
    pcs = "http://localhost:4566"
    ec2 = "http://localhost:4566"
    kms = "http://localhost:4566"
    iam = "http://localhost:4566"
    sts = "http://localhost:4566"
  }
}

# 1. Buat VPC (Cloud Network)
resource "aws_vpc" "my_vpc" {
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "VPC-Belajar-Localstack"
  }

  # Skip VPC Flow Logs karena tidak diperlukan untuk testing lokal
  #checkov:skip=CKV2_AWS_11: "VPC Flow logging is disabled for local environment"
}

# Mengunci Default Security Group agar tidak mengizinkan trafik inbound/outbound bebas (Fix CKV2_AWS_12)
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.my_vpc.id
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.my_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = false

  tags = {
    Name = "Public-Subnet-Web"
  }
}

resource "aws_subnet" "private_subnet" {
  vpc_id     = aws_vpc.my_vpc.id
  cidr_block = "10.0.2.0/24"

  tags = {
    Name = "Private-Subnet-DB"
  }
} 

# 2. Buat S3 Bucket (Storage)
resource "aws_s3_bucket" "my_bucket" {
  bucket = "s3-bucket-belajar-sneks"

  # Skip aturan enterprise yang berlebihan untuk bucket lokal
  #checkov:skip=CKV_AWS_144: "Cross-region replication not needed for dev bucket"
  #checkov:skip=CKV2_AWS_62: "Event notifications not required for dev bucket"
  #checkov:skip=CKV2_AWS_61: "Lifecycle configuration not required for dev bucket"
  #checkov:skip=CKV_AWS_18: "Access logging disabled for dev bucket"
}

# A. Blokir Semua Akses Publik (Fix CKV2_AWS_6) - KRUSIAL
resource "aws_s3_bucket_public_access_block" "my_bucket_pab" {
  bucket = aws_s3_bucket.my_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# B. Aktifkan Versioning untuk Cegah File Terhapus (Fix CKV_AWS_21)
resource "aws_s3_bucket_versioning" "my_bucket_versioning" {
  bucket = aws_s3_bucket.my_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# 3. Buat Customer Managed Key (CMK) di AWS KMS
data "aws_caller_identity" "current" {}

resource "aws_kms_key" "s3_key" {
  description             = "Kunci KMS untuk enkripsi S3 Bucket s3-bucket-belajar-sneks"
  deletion_window_in_days = 7
  enable_key_rotation     = true # Menjawab standar keamanan (Fix CKV_AWS_7)

  # FIX CKV2_AWS_64: Mendefinisikan KMS Key Policy secara eksplisit
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "kms-key-policy-s3"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        # Memberikan hak pengelolaan KMS ke Root Account agar bisa didelegasikan via IAM Policy
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "kms-s3-belajar"
  }
}

# Membuat nama alias agar KMS Key mudah dikenali
resource "aws_kms_alias" "s3_key_alias" {
  name          = "alias/s3-belajar-key"
  target_key_id = aws_kms_key.s3_key.key_id
}

# 2. Hubungkan S3 Bucket Encryption ke KMS Key Resmi yang Baru Dibuat
resource "aws_s3_bucket_server_side_encryption_configuration" "my_bucket_encryption" {
  bucket = aws_s3_bucket.my_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3_key.arn # Merujuk ke ARN KMS buatan sendiri
      sse_algorithm     = "aws:kms"
    }
  }
}

# 4. IAM Role (Trust Policy): Menentukan SIAPA yang boleh menggunakan role ini
resource "aws_iam_role" "app_s3_role" {
  name = "app-s3-access-role"

  # Menizinkan service EC2 untuk mengambil (assume) role ini
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "ec2.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

# IAM Policy (Permission Policy): Menentukan APA SAJA yang boleh dilakukan
resource "aws_iam_policy" "app_s3_policy" {
  name        = "app-s3-read-write-policy"
  description = "Izin Least Privilege untuk membaca/menulis ke S3 terenkripsi KMS"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # A. Hanya izin melihat daftar file (butuh ARN Bucket)
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = [aws_s3_bucket.my_bucket.arn]
      },
      # B. Hanya izin baca & tulis file (butuh ARN Bucket + /*)
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = ["${aws_s3_bucket.my_bucket.arn}/*"]
      },
      # C. Izin KMS (Wajib ada karena S3 terenkripsi KMS!)
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [aws_kms_key.s3_key.arn]
      }
    ]
  })
}

# Menempelkan IAM Policy ke IAM Role
resource "aws_iam_role_policy_attachment" "app_s3_attach" {
  role       = aws_iam_role.app_s3_role.name
  policy_arn = aws_iam_policy.app_s3_policy.arn
}

# Instance Profile: Wadah agar IAM Role bisa dipasang langsung ke EC2
resource "aws_iam_instance_profile" "app_s3_profile" {
  name = "app-s3-instance-profile"
  role = aws_iam_role.app_s3_role.name
}