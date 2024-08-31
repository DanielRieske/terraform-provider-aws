// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssoadmin

// Exports for use in tests only.
var (
	ResourceApplication                        = newResourceApplication
	ResourceApplicationAccessScope             = newResourceApplicationAccessScope
	ResourceApplicationAssignment              = newResourceApplicationAssignment
	ResourceApplicationAssignmentConfiguration = newResourceApplicationAssignmentConfiguration
	ResourceApplicationAuthenticationMethod    = newResourceApplicationAuthenticationMethod
	ResourceTrustedTokenIssuer                 = newResourceTrustedTokenIssuer

	FindApplicationByID                                              = findApplicationByID
	FindApplicationAccessScopeByID                                   = findApplicationAccessScopeByID
	FindApplicationAssignmentByID                                    = findApplicationAssignmentByID
	FindApplicationAssignmentConfigurationByID                       = findApplicationAssignmentConfigurationByID
	FindApplicationAuthenticationMethodByMethodTypeAndApplicationARN = findApplicationAuthenticationMethodByMethodTypeAndApplicationARN
	FindTrustedTokenIssuerByARN                                      = findTrustedTokenIssuerByARN
)
