# METADATA
# title: "Sin límites de memoria o de procesos"
# description: "Sin límites de memoria y de PIDs un contenedor puede agotar los recursos del anfitrión (CIS Docker 5.11 y 5.29, OWASP Rule #7)."
# scope: package
# custom:
#   id: HLC-004
#   avd_id: HLC-004
#   provider: compose
#   service: runtime
#   severity: MEDIUM
#   short_code: hlc004
#   recommended_action: "Definir mem_limit y pids_limit."
#   input:
#     selector:
#       - type: yaml
package user.compose.hlc004

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
	not has_limits(svc)
	msg := sprintf("[%s] no define mem_limit y pids_limit", [name])
	res := result.new(msg, {})
}
