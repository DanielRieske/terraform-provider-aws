// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package verifiedpermissions

// Exports for use in tests only.
var (
	ResourcePolicy         = newResourcePolicy
	ResourcePolicyStore    = newResourcePolicyStore
	ResourcePolicyTemplate = newResourcePolicyTemplate
	ResourceSchema         = newResourceSchema
	ResourceIdentitySource = newResourceIdentitySource

	FindPolicyByID            = findPolicyByID
	FindPolicyStoreByID       = findPolicyStoreByID
	FindPolicyTemplateByID    = findPolicyTemplateByID
	FindSchemaByPolicyStoreID = findSchemaByPolicyStoreID
	FindIdentitySourceByID    = findIdentitySourceByID
)

var (
	PolicyTemplateParseID = policyTemplateParseID
)
