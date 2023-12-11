// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssoadmin_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/service/ssoadmin"
	tfssoadmin "github.com/hashicorp/terraform-provider-aws/internal/service/ssoadmin"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func TestAccSSOAdminApplicationAuthenticationMethod_basic(t *testing.T) {
	ctx := acctest.Context(t)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_ssoadmin_application_authentication_method.test"
	applicationResourceName := "aws_ssoadmin_application.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); acctest.PreCheckSSOAdminInstances(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.SSOAdminEndpointID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckApplicationAuthenticationMethodDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationAuthenticationMethodConfigBase(rName, string(types.AuthenticationMethodTypeIam)),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckApplicationAuthenticationMethodExists(ctx, resourceName),
					resource.TestCheckResourceAttrPair(resourceName, "application_arn", applicationResourceName, "application_arn"),
					resource.TestCheckResourceAttr(resourceName, "authentication_method_type", string(types.AuthenticationMethodTypeIam)),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateIdFunc: testAccApplicationAuthenticationMethodImportStateIdFunc(resourceName),
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccSSOAdminApplicationAuthenticationMethod_disappears(t *testing.T) {
	ctx := acctest.Context(t)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_ssoadmin_application_authentication_method.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t); acctest.PreCheckSSOAdminInstances(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.SSOAdminEndpointID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckApplicationAuthenticationMethodDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationAuthenticationMethodConfigBase(rName, string(types.AuthenticationMethodTypeIam)),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckApplicationAuthenticationMethodExists(ctx, resourceName),
					acctest.CheckFrameworkResourceDisappears(ctx, acctest.Provider, tfssoadmin.ResourceApplicationAssignment, resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccCheckApplicationAuthenticationMethodExists(ctx context.Context, n string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).SSOAdminClient(ctx)

		applicationARN, authenticationMethodType, err := ssoadmin.ApplicationAuthenticationMethodParseResourceID(rs.Primary.ID)
		if err != nil {
			return err
		}

		_, err = ssoadmin.FindApplicationAuthenticationMethodByMethodTypeAndApplicationARN(ctx, conn, applicationARN, authenticationMethodType)

		return err
	}
}

func testAccCheckApplicationAuthenticationMethodDestroy(ctx context.Context) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).SSOAdminClient(ctx)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_ssoadmin_application_authentication_method" {
				continue
			}

			var applicationARN, authenticationMethodType, err = ssoadmin.ApplicationAuthenticationMethodParseResourceID(rs.Primary.ID)
			if err != nil {
				return err
			}

			_, err = ssoadmin.FindApplicationAuthenticationMethodByMethodTypeAndApplicationARN(ctx, conn, applicationARN, authenticationMethodType)

			if tfresource.NotFound(err) {
				continue
			}

			if err != nil {
				return err
			}

			return fmt.Errorf("SSO Application Authentication Method %s still exists", rs.Primary.ID)
		}

		return nil
	}
}

func testAccApplicationAuthenticationMethodImportStateIdFunc(resourceName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("Not Found: %s", resourceName)
		}

		return fmt.Sprintf("%s,%s", rs.Primary.Attributes["application_arn"], rs.Primary.Attributes["authentication_method_type"]), nil
	}
}

func testAccApplicationAuthenticationMethodConfigBase(rName, authenticationMethodType string) string {
	return fmt.Sprintf(`
data "aws_ssoadmin_instances" "test" {}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

resource "aws_ssoadmin_application" "test" {
  name                     = %[1]q
  application_provider_arn = %[2]q
  instance_arn             = tolist(data.aws_ssoadmin_instances.test.arns)[0]
}

resource "aws_ssoadmin_application_authentication_method" "test" {
  application_arn            = aws_ssoadmin_application.test.application_arn
  authentication_method_type = %[3]q

  authentication_method {
    iam {
      actor_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [{
          Action = "sso-oauth:CreateTokenWithIAM",
          Principal = {
            AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
          }
          Effect   = "Allow"
          Resource = "*"
        }]
      })
    }
  }
}
`, rName, testAccApplicationProviderARN, authenticationMethodType)
}
