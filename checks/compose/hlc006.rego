# METADATA
# title: "Socket de Docker montado en el contenedor"
# description: "Acceso a docker.sock equivale a root en el anfitrión (OWASP Rule #1, CIS Docker 5.32)."
# scope: package
# custom:
#   id: HLC-006
#   avd_id: HLC-006
#   provider: compose
#   service: runtime
#   severity: CRITICAL
#   short_code: hlc006
#   recommended_action: "No montar /var/run/docker.sock en servicios del laboratorio."
#   input:
#     selector:
#       - type: yaml
package user.compose.hlc006

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
	some v in svc.volumes
	contains(v.source, "docker.sock")
	msg := sprintf("[%s] monta el socket de Docker", [name])
	res := result.new(msg, {})
}
