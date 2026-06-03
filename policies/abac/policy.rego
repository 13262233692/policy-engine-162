package abac

default allow := false

allow if {
	rbac_allow
}

allow if {
	abac_allow
}

allow if {
	spatial_allow
}

rbac_allow if {
	some role in input.subject.roles
	some perm in data.roles[role]
	perm.action == input.action.name
	perm.resource == input.resource.type
}

abac_allow if {
	input.action.name == "read"
	input.resource.classification == "public"
}

abac_allow if {
	input.action.name == "read"
	input.resource.classification == "internal"
	"employee" in input.subject.roles
}

abac_allow if {
	input.action.name == "read"
	input.resource.classification == "confidential"
	"employee" in input.subject.roles
	input.subject.department == input.resource.department
}

abac_allow if {
	input.action.name == "write"
	input.resource.owner == input.subject.id
}

abac_allow if {
	input.action.name == "write"
	"admin" in input.subject.roles
}

abac_allow if {
	input.action.name == "delete"
	"admin" in input.subject.roles
}

spatial_allow if {
	input.action.name == "read"
	input.resource.classification == "internal"
	input.context.location == input.subject.location
}

deny_reason := "insufficient_permissions" if {
	not allow
	not has_any_role
}

deny_reason := "department_mismatch" if {
	not allow
	input.resource.classification == "confidential"
	input.subject.department != input.resource.department
}

deny_reason := "location_restriction" if {
	not allow
	input.context.location != input.subject.location
	input.resource.classification == "internal"
}

deny_reason := "access_denied" if {
	not allow
}

has_any_role if {
	count(input.subject.roles) > 0
}

obligations := {
	"log_access": true,
	"notify_owner": true,
} if {
	input.action.name == "delete"
	"admin" in input.subject.roles
}

obligations := {
	"log_access": true,
} if {
	input.action.name != "delete"
	allow
}
