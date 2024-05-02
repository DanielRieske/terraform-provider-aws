// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package verifiedpermissions_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/YakDriver/regexache"
	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	tfverifiedpermissions "github.com/hashicorp/terraform-provider-aws/internal/service/verifiedpermissions"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func TestAccVerifiedPermissionsIdentitySource_basic(t *testing.T) {
	ctx := acctest.Context(t)
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	var policystore verifiedpermissions.GetIdentitySourceOutput
	resourceName := "aws_verifiedpermissions_identity_source.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckPartitionHasService(t, names.VerifiedPermissionsEndpointID)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.VerifiedPermissionsServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckIdentitySourceDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccIdentitySourceConfig_basic("OFF"),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckIdentitySourceExists(ctx, resourceName, &policystore),
					resource.TestCheckResourceAttr(resourceName, "validation_settings.0.mode", "OFF"),
					resource.TestCheckResourceAttr(resourceName, "description", "Terraform acceptance test"),
					acctest.MatchResourceAttrGlobalARN(resourceName, "arn", "verifiedpermissions", regexache.MustCompile(`policy-store/+.`)),
				),
			},
			{
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

func TestAccVerifiedPermissionsIdentitySource_update(t *testing.T) {
	ctx := acctest.Context(t)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	var policystore verifiedpermissions.GetIdentitySourceOutput
	resourceName := "aws_verifiedpermissions_identity_source.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckPartitionHasService(t, names.VerifiedPermissionsEndpointID)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.VerifiedPermissionsServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckIdentitySourceDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccIdentitySourceConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckIdentitySourceExists(ctx, resourceName, &policystore),
					resource.TestCheckResourceAttr(resourceName, "validation_settings.0.mode", "OFF"),
				),
			},
			{
				Config: testAccIdentitySourceConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "validation_settings.0.mode", "STRICT"),
				),
			},
		},
	})
}

func TestAccVerifiedPermissionsIdentitySource_disappears(t *testing.T) {
	ctx := acctest.Context(t)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	if testing.Short() {
		t.Skip("skipping long-running test in short mode")
	}

	var policystore verifiedpermissions.GetIdentitySourceOutput
	resourceName := "aws_verifiedpermissions_policy_store.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckPartitionHasService(t, names.VerifiedPermissionsEndpointID)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.VerifiedPermissionsServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckIdentitySourceDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccIdentitySourceConfig_basic(rName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckIdentitySourceExists(ctx, resourceName, &policystore),
					acctest.CheckFrameworkResourceDisappears(ctx, acctest.Provider, tfverifiedpermissions.ResourceIdentitySource, resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccCheckIdentitySourceDestroy(ctx context.Context) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).VerifiedPermissionsClient(ctx)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_verifiedpermissions_identity_source" {
				continue
			}

			_, err := tfverifiedpermissions.FindIdentitySourceByID(ctx, conn, rs.Primary.ID)

			if tfresource.NotFound(err) {
				continue
			}

			if err != nil {
				return err
			}

			return create.Error(names.VerifiedPermissions, create.ErrActionCheckingDestroyed, tfverifiedpermissions.ResNameIdentitySource, rs.Primary.ID, errors.New("not destroyed"))
		}

		return nil
	}
}

func testAccCheckIdentitySourceExists(ctx context.Context, name string, policystore *verifiedpermissions.GetIdentitySourceOutput) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return create.Error(names.VerifiedPermissions, create.ErrActionCheckingExistence, tfverifiedpermissions.ResNameIdentitySource, name, errors.New("not found"))
		}

		if rs.Primary.ID == "" {
			return create.Error(names.VerifiedPermissions, create.ErrActionCheckingExistence, tfverifiedpermissions.ResNameIdentitySource, name, errors.New("not set"))
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).VerifiedPermissionsClient(ctx)
		resp, err := tfverifiedpermissions.FindIdentitySourceByID(ctx, conn, rs.Primary.ID)

		if err != nil {
			return create.Error(names.VerifiedPermissions, create.ErrActionCheckingExistence, tfverifiedpermissions.ResNameIdentitySource, rs.Primary.ID, err)
		}

		*policystore = *resp

		return nil
	}
}

func testAccIdentitySourceConfig_basic(rName string) string {
	return fmt.Sprintf(`
resource "aws_cognito_user_pool" "test" {
  name = %[1]q
}

resource "aws_verifiedpermissions_policy_store" "test" {
  description = "Terraform acceptance test"
  validation_settings {
    mode = "OFF"
  }
}

resource "aws_verifiedpermissions_identity_source" "test" {
  policy_store_id = aws_verifiedpermissions_policy_store.test.id
  configuration {
    cognito_user_pool_configuration {
      user_pool_arn = aws_cognito_user_pool.test.arn
      client_ids    = ["test"]

      group_configuration {
        group_entity_type = "AWS::CognitoGroup"
      }
    }
  }
}
`, rName)
}
