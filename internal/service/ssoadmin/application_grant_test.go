// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssoadmin_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	awstypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	sdkacctest "github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	tfssoadmin "github.com/hashicorp/terraform-provider-aws/internal/service/ssoadmin"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func TestAccSSOAdminApplicationGrant_basic(t *testing.T) {
	ctx := acctest.Context(t)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_ssoadmin_application_grant.test"
	applicationResourceName := "aws_ssoadmin_application.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckPartitionHasService(t, names.SSOAdminEndpointID)
			acctest.PreCheckSSOAdminInstances(ctx, t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.SSOAdminServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckApplicationGrantDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationGrantConfig_basic(rName, string(awstypes.GrantTypeAuthorizationCode)),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckApplicationGrantExists(ctx, resourceName),
					resource.TestCheckResourceAttrPair(resourceName, "application_arn", applicationResourceName, "application_arn"),
					resource.TestCheckResourceAttr(resourceName, "grant_type", string(awstypes.GrantTypeAuthorizationCode)),
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

func TestAccSSOAdminApplicationGrant_JwtBearer(t *testing.T) {
	ctx := acctest.Context(t)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_ssoadmin_application_grant.test"
	applicationResourceName := "aws_ssoadmin_application.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckPartitionHasService(t, names.SSOAdminEndpointID)
			acctest.PreCheckSSOAdminInstances(ctx, t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.SSOAdminServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckApplicationGrantDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationGrantConfig_JwtBearer(rName, string(awstypes.GrantTypeJwtBearer)),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckApplicationGrantExists(ctx, resourceName),
					resource.TestCheckResourceAttrPair(resourceName, "application_arn", applicationResourceName, "application_arn"),
					resource.TestCheckResourceAttr(resourceName, "grant_type", string(awstypes.GrantTypeJwtBearer)),
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

func TestAccSSOAdminApplicationGrant_disappears(t *testing.T) {
	ctx := acctest.Context(t)
	rName := sdkacctest.RandomWithPrefix(acctest.ResourcePrefix)
	resourceName := "aws_ssoadmin_application_grant.test"

	resource.ParallelTest(t, resource.TestCase{
		PreCheck: func() {
			acctest.PreCheck(ctx, t)
			acctest.PreCheckPartitionHasService(t, names.SSOAdminEndpointID)
			acctest.PreCheckSSOAdminInstances(ctx, t)
		},
		ErrorCheck:               acctest.ErrorCheck(t, names.SSOAdminServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		CheckDestroy:             testAccCheckApplicationGrantDestroy(ctx),
		Steps: []resource.TestStep{
			{
				Config: testAccApplicationGrantConfig_basic(rName, string(awstypes.GrantTypeAuthorizationCode)),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckApplicationGrantExists(ctx, resourceName),
					acctest.CheckFrameworkResourceDisappears(ctx, acctest.Provider, tfssoadmin.ResourceApplicationGrant, resourceName),
				),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccCheckApplicationGrantDestroy(ctx context.Context) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		conn := acctest.Provider.Meta().(*conns.AWSClient).SSOAdminClient(ctx)

		for _, rs := range s.RootModule().Resources {
			if rs.Type != "aws_ssoadmin_application_grant" {
				continue
			}

			_, err := tfssoadmin.FindApplicationGrantByID(ctx, conn, rs.Primary.ID)
			if errs.IsA[*awstypes.ResourceNotFoundException](err) {
				return nil
			}
			if err != nil {
				return create.Error(names.SSOAdmin, create.ErrActionCheckingDestroyed, tfssoadmin.ResNameApplicationGrant, rs.Primary.ID, err)
			}

			return create.Error(names.SSOAdmin, create.ErrActionCheckingDestroyed, tfssoadmin.ResNameApplicationGrant, rs.Primary.ID, errors.New("not destroyed"))
		}

		return nil
	}
}

func testAccCheckApplicationGrantExists(ctx context.Context, name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[name]
		if !ok {
			return create.Error(names.SSOAdmin, create.ErrActionCheckingExistence, tfssoadmin.ResNameApplicationGrant, name, errors.New("not found"))
		}

		if rs.Primary.ID == "" {
			return create.Error(names.SSOAdmin, create.ErrActionCheckingExistence, tfssoadmin.ResNameApplicationGrant, name, errors.New("not set"))
		}

		conn := acctest.Provider.Meta().(*conns.AWSClient).SSOAdminClient(ctx)

		_, err := tfssoadmin.FindApplicationGrantByID(ctx, conn, rs.Primary.ID)
		if err != nil {
			return create.Error(names.SSOAdmin, create.ErrActionCheckingExistence, tfssoadmin.ResNameApplicationGrant, rs.Primary.ID, err)
		}

		return nil
	}
}

func testAccApplicationGrantConfigBase(rName string) string {
	return fmt.Sprintf(`
data "aws_ssoadmin_instances" "test" {}

resource "aws_ssoadmin_application_access_scope" "test" {
	application_arn    = aws_ssoadmin_application.test.application_arn
	authorized_targets = [aws_ssoadmin_application.test.application_arn]
	scope              = "sso:account:access"
  }

resource "aws_ssoadmin_application" "test" {
  name                     = %[1]q
  application_provider_arn = %[2]q
  instance_arn             = tolist(data.aws_ssoadmin_instances.test.arns)[0]
}
`, rName, testAccApplicationProviderARN)
}

func testAccApplicationGrantConfig_basic(rName, grantType string) string {
	return acctest.ConfigCompose(
		testAccApplicationGrantConfigBase(rName),
		fmt.Sprintf(`
resource "aws_ssoadmin_application_grant" "test" {
  application_arn = aws_ssoadmin_application.test.application_arn
  grant_type      = %[1]q

  grant {
    authorization_code {
      redirect_uris = ["uri"]
    }
  }
}
`, grantType))
}

func testAccApplicationGrantConfig_JwtBearer(rName, grantType string) string {
	return acctest.ConfigCompose(
		testAccApplicationGrantConfigBase(rName),
		fmt.Sprintf(`
resource "aws_ssoadmin_trusted_token_issuer" "test" {
  name                      = %[1]q
  instance_arn              = tolist(data.aws_ssoadmin_instances.test.arns)[0]
  trusted_token_issuer_type = "OIDC_JWT"

  trusted_token_issuer_configuration {
    oidc_jwt_configuration {
      claim_attribute_path          = "email"
      identity_store_attribute_path = "emails.value"
      issuer_url                    = "https://example.com"
      jwks_retrieval_option         = "OPEN_ID_DISCOVERY"
    }
  }
}

resource "aws_ssoadmin_application_grant" "test" {
  application_arn = aws_ssoadmin_application.test.application_arn
  grant_type      = %[2]q

  grant {
    jwt_bearer {
      authorized_token_issuers {
        authorized_audiences     = ["test"]
        trusted_token_issuer_arn = aws_ssoadmin_trusted_token_issuer.test.arn
      }
    }
  }
}
`, rName, grantType))
}
