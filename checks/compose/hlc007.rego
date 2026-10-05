# METADATA
# title: "Puerto de base de datos publicado en el anfitrión"
# description: "La base de datos solo debe ser alcanzable desde la capa web por una red interna."
# scope: package
# custom:
#   id: HLC-007
#   avd_id: HLC-007
#   provider: compose
#   service: runtime
#   severity: HIGH
#   short_code: hlc007
#   recommended_action: "No publicar 5432; usar una red interna compartida con la capa web."
#   input:
#     selector:
#       - type: yaml
package user.compose.hlc007

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
	some p in svc.ports
	p.target == 5432
	msg := sprintf("[%s] publica el puerto 5432 en el anfitrión", [name])
	res := result.new(msg, {})
}
