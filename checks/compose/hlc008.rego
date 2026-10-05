# METADATA
# title: "Sin no-new-privileges"
# description: "Sin no-new-privileges un proceso puede ganar privilegios con binarios setuid (CIS Docker 5.26, OWASP Rule #4)."
# scope: package
# custom:
#   id: HLC-008
#   avd_id: HLC-008
#   provider: compose
#   service: runtime
#   severity: MEDIUM
#   short_code: hlc008
#   recommended_action: "Agregar security_opt: [no-new-privileges:true]."
#   input:
#     selector:
#       - type: yaml
package user.compose.hlc008

import rego.v1

lab_services contains [name, svc] if {
	some _, svc in input.services
	svc.labels["hlab.lab"] == "true"
	name := object.get(svc, "container_name", "unknown")
}

drops_all(svc) if {
	some c in svc.cap_drop
	upper(c) == "ALL"
}

has_limits(svc) if {
	svc.mem_limit
	svc.pids_limit
}

no_new_privileges(svc) if {
	some opt in svc.security_opt
	startswith(opt, "no-new-privileges")
	not endswith(opt, "false")
}

deny contains res if {
	some [name, svc] in lab_services
	not no_new_privileges(svc)
	msg := sprintf("[%s] no declara no-new-privileges", [name])
	res := result.new(msg, {})
}
