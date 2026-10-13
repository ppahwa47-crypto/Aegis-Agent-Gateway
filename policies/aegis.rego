package aegis

import rego.v1

policy_id := "aegis/v1"

tenant_ok if {
	parts := split(input.capability.resource, "/")
	count(parts) == 6
	parts[0] == "tenants"
	parts[1] == input.grant.tenant
	parts[2] == "projects"
	parts[1] in {"acme", "bravo"}
	parts[3] in {"alpha", "beta"}
	regex.match(`^tenants/[a-z0-9-]+/projects/[a-z0-9-]+/(docs|tickets|exports)/[a-z0-9][a-z0-9._-]{0,63}$`, input.capability.resource)
}

capability_ok if {
	some cap in input.grant.capabilities
	cap == input.capability
}

operation_ok if {
	input.capability.tool == "docs.read"
	split(input.capability.resource, "/")[4] == "docs"
	input.capability.destination == ""
}

operation_ok if {
	input.capability.tool == "tickets.create"
	split(input.capability.resource, "/")[4] == "tickets"
	input.capability.destination == ""
}

operation_ok if {
	input.capability.tool == "exports.upload"
	parts := split(input.capability.resource, "/")
	parts[4] == "exports"
	input.capability.destination == sprintf("vault://%s/%s", [parts[1], parts[3]])
}

reason := "tenant_boundary" if not tenant_ok

else := "capability_missing" if not capability_ok

else := "operation_or_destination_denied" if not operation_ok

else := "secret_detected" if input.secret

else := "confidential_write" if {
	input.confidential
	input.capability.tool != "docs.read"
}

else := "authorized"

decision := {"allow": reason == "authorized", "reason": reason, "policy": policy_id}
