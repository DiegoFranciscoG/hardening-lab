# METADATA
# title: "Política de reinicio sin tope"
# description: "restart: always o unless-stopped reinicia sin límite y oculta fallas; CIS Docker 5.15 recomienda on-failure con un máximo de 5."
# scope: package
# custom:
#   id: HLC-005
#   avd_id: HLC-005
#   provider: compose
#   service: runtime
#   severity: LOW
#   short_code: hlc005
#   recommended_action: "Usar restart: on-failure:5."
#   input:
#     selector:
#       - type: yaml
package user.compose.hlc005

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
	svc.restart in {"always", "unless-stopped"}
	msg := sprintf("[%s] usa restart: %s", [name, svc.restart])
	res := result.new(msg, {})
}
