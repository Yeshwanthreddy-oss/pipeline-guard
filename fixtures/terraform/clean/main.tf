# Policy-compliant counterpart to fixtures/terraform/vulnerable/main.tf

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_s3_bucket" "assets" {
  bucket = "demo-private-assets"
  acl    = "private"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
}

resource "aws_db_instance" "primary" {
  engine                 = "postgres"
  instance_class         = "db.t3.medium"
  allocated_storage      = 100
  publicly_accessible    = false
  storage_encrypted      = true
}
