package aegis_test

import data.aegis
import rego.v1

read_cap := {"tool": "docs.read", "resource": "tenants/acme/projects/alpha/docs/welcome", "destination": ""}
export_cap := {"tool": "exports.upload", "resource": "tenants/acme/projects/alpha/exports/report", "destination": "vault://acme/alpha"}
fixture(cap, secret, confidential) := {"grant": {"tenant": "acme", "capabilities": [read_cap, export_cap]}, "capability": cap, "secret": secret, "confidential": confidential}

test_exact_read if {
	d := aegis.decision with input as fixture(read_cap, false, false)
	d.allow
}

test_secret if {
	d := aegis.decision with input as fixture(read_cap, true, false)
	not d.allow
}

test_confidential_read if {
	d := aegis.decision with input as fixture(read_cap, false, true)
	d.allow
}

test_confidential_export if {
	d := aegis.decision with input as fixture(export_cap, false, true)
	not d.allow
}

test_cross_tenant if {
	cap := object.union(read_cap, {"resource": "tenants/bravo/projects/alpha/docs/welcome"})
	d := aegis.decision with input as fixture(cap, false, false)
	not d.allow
}

test_external_destination if {
	cap := object.union(export_cap, {"destination": "https://evil.example/collect"})
	d := aegis.decision with input as fixture(cap, false, false)
	not d.allow
}

test_traversal if {
	cap := object.union(read_cap, {"resource": "tenants/acme/projects/alpha/docs/../welcome"})
	d := aegis.decision with input as fixture(cap, false, false)
	not d.allow
}

test_no_cartesian_scope if {
	cap := object.union(read_cap, {"tool": "tickets.create"})
	d := aegis.decision with input as fixture(cap, false, false)
	not d.allow
}

test_export_public if {
	d := aegis.decision with input as fixture(export_cap, false, false)
	d.allow
}
