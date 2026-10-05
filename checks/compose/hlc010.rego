# METADATA
# title: "Base de datos en una red con salida"
# description: "La capa de datos debe vivir solo en redes internas, sin salida a Internet ni a la red de administración del anfitrión."
# scope: package
# custom:
#   id: HLC-010
#   avd_id: HLC-010
#   provider: compose
#   service: runtime
#   severity: HIGH
#   short_code: hlc010
#   recommended_action: "Conectar la base de datos solo a redes con internal: true."
#   input:
#     selector:
#       - type: yaml
package user.compose.hlc010

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
	name == "lab-db"
	some net_name, _ in svc.networks
	not input.networks[net_name].internal
	msg := sprintf("[%s] está conectada a la red no interna %s", [name, net_name])
	res := result.new(msg, {})
}
