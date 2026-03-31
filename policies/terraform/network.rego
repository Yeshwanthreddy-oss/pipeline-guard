package terraform.network

# Deny security groups that allow ingress from the public internet.
#
# Run for real with:
#   terraform show -json plan.tfplan > plan.json
#   conftest test --policy policies/terraform plan.json
#
# This is the canonical OPA form of the check pipeline-guard's built-in
# engine implements in Python (scanners/terraform_policy.py::check_open_security_groups)
# so a team with `conftest` installed can enforce the identical rule via a
# standard `conftest test` step instead of (or alongside) the CLI.

any_cidr := {"0.0.0.0/0", "::/0"}

sensitive_ports := {22, 3389, 3306, 5432, 6379, 9200, 27017}

deny[msg] {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group"
	rule := resource.change.after.ingress[_]
	some cidr
	cidr := rule.cidr_blocks[_]
	any_cidr[cidr]
	sensitive_ports[rule.from_port]
	msg := sprintf(
		"%s: ingress rule allows %v/%v from %v on a sensitive port",
		[resource.address, rule.from_port, rule.to_port, cidr],
	)
}

warn[msg] {
	resource := input.resource_changes[_]
	resource.type == "aws_security_group"
	rule := resource.change.after.ingress[_]
	some cidr
	cidr := rule.cidr_blocks[_]
	any_cidr[cidr]
	not sensitive_ports[rule.from_port]
	msg := sprintf(
		"%s: ingress rule allows %v/%v from %v",
		[resource.address, rule.from_port, rule.to_port, cidr],
	)
}

deny[msg] {
	resource := input.resource_changes[_]
	resource.type == "aws_db_instance"
	resource.change.after.publicly_accessible == true
	msg := sprintf("%s: RDS instance is publicly_accessible", [resource.address])
}
