package terraform.encryption

# Deny storage resources that are not encrypted at rest, and S3 buckets that
# are directly public. Canonical OPA form of
# scanners/terraform_policy.py::check_missing_encryption /
# check_public_storage -- see policies/README.md for how the built-in
# Python engine and these .rego files stay in sync.

encrypted_attr := {
	"aws_ebs_volume": "encrypted",
	"aws_db_instance": "storage_encrypted",
	"aws_sqs_queue": "kms_master_key_id",
}

deny[msg] {
	resource := input.resource_changes[_]
	attr := encrypted_attr[resource.type]
	not resource.change.after[attr]
	msg := sprintf("%s: missing `%s = true` (data at rest is unencrypted)", [resource.address, attr])
}

deny[msg] {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket"
	resource.change.after.acl == "public-read"
	msg := sprintf("%s: bucket ACL is public-read", [resource.address])
}

deny[msg] {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket"
	resource.change.after.acl == "public-read-write"
	msg := sprintf("%s: bucket ACL is public-read-write", [resource.address])
}

deny[msg] {
	resource := input.resource_changes[_]
	resource.type == "aws_s3_bucket_public_access_block"
	after := resource.change.after
	not (after.block_public_acls == true)
	msg := sprintf("%s: block_public_acls is not true", [resource.address])
}
