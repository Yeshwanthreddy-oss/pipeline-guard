# Intentionally vulnerable Terraform fixture for pipeline-guard's policy
# engine tests and the auto-fix demo. Do not deploy this.

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "assets" {
  bucket = "demo-public-assets"
  acl    = "public-read"
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 40
}

resource "aws_db_instance" "primary" {
  engine                 = "postgres"
  instance_class         = "db.t3.medium"
  allocated_storage      = 100
  publicly_accessible    = true
  storage_encrypted      = false
}
