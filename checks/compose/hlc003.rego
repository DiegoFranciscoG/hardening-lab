# METADATA
# title: "Contenedor privilegiado"
# description: "Un contenedor privilegiado no está aislado del anfitrión (CIS Docker 5.5)."
# scope: package
# custom:
#   id: HLC-003
#   avd_id: HLC-003
#   provider: compose
#   service: runtime
#   severity: CRITICAL
#   short_code: hlc003
#   recommended_action: "Eliminar privileged: true y conceder capacidades puntuales."
#   input:
#     selector:
#       - type: yaml
package user.compose.hlc003

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
	svc.privileged == true
	msg := sprintf("[%s] corre en modo privilegiado", [name])
	res := result.new(msg, {})
}
