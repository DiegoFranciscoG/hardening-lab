# METADATA
# title: "Puerto publicado en todas las interfaces del anfitrión"
# description: "Un puerto publicado sin host_ip queda expuesto en todas las interfaces del anfitrión; Docker además salta reglas de UFW (OWASP Docker Rule #5a)."
# scope: package
# custom:
#   id: HLC-001
#   avd_id: HLC-001
#   provider: compose
#   service: runtime
#   severity: HIGH
#   short_code: hlc001
#   recommended_action: "Publicar solo en 127.0.0.1 o no publicar el puerto."
#   input:
#     selector:
#       - type: yaml
package user.compose.hlc001

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
	not p.host_ip
	msg := sprintf("[%s] publica el puerto %v en todas las interfaces", [name, p.target])
	res := result.new(msg, {})
}
