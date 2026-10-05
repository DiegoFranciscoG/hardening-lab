# METADATA
# title: "El contenedor conserva las capacidades por defecto"
# description: "Docker concede por defecto un conjunto de capacidades; el principio de mínimo privilegio pide quitarlas todas y agregar solo las necesarias (CIS Docker 5.3, OWASP Rule #3)."
# scope: package
# custom:
#   id: HLC-002
#   avd_id: HLC-002
#   provider: compose
#   service: runtime
#   severity: MEDIUM
#   short_code: hlc002
#   recommended_action: "Agregar cap_drop: [ALL] y cap_add solo con lo imprescindible."
#   input:
#     selector:
#       - type: yaml
package user.compose.hlc002

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
	not drops_all(svc)
	msg := sprintf("[%s] no declara cap_drop: [ALL]", [name])
	res := result.new(msg, {})
}
