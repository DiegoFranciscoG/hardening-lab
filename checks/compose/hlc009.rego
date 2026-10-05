# METADATA
# title: "Sistema de archivos raíz escribible"
# description: "Un sistema de archivos raíz de solo lectura reduce la persistencia de un atacante (CIS Docker 5.13, NIST SP 800-190)."
# scope: package
# custom:
#   id: HLC-009
#   avd_id: HLC-009
#   provider: compose
#   service: runtime
#   severity: LOW
#   short_code: hlc009
#   recommended_action: "Usar read_only: true con tmpfs para las rutas que deban escribirse."
#   input:
#     selector:
#       - type: yaml
package user.compose.hlc009

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
	not svc.read_only
	msg := sprintf("[%s] tiene el sistema de archivos raíz escribible", [name])
	res := result.new(msg, {})
}
