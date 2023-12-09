// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssoadmin

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin/document"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/structure"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/enum"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
)

// @SDKResource("aws_ssoadmin_application_authentication_method")
func ResourceApplicationAuthenticationMethod() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceApplicationAuthenticationMethodCreate,
		ReadWithoutTimeout:   resourceApplicationAuthenticationMethodRead,
		DeleteWithoutTimeout: resourceApplicationAuthenticationMethodDelete,

		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Timeouts: &schema.ResourceTimeout{
			Create: schema.DefaultTimeout(10 * time.Minute),
			Delete: schema.DefaultTimeout(10 * time.Minute),
		},

		Schema: map[string]*schema.Schema{
			"application_arn": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: verify.ValidARN,
			},
			"authentication_method": {
				Type:     schema.TypeList,
				Required: true,
				ForceNew: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"iam": {
							Type:     schema.TypeList,
							Optional: true,
							ForceNew: true,
							MaxItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"actor_policy": {
										Type:                  schema.TypeString,
										Required:              true,
										ForceNew:              true,
										ValidateFunc:          verify.ValidIAMPolicyJSON,
										DiffSuppressFunc:      verify.SuppressEquivalentPolicyDiffs,
										DiffSuppressOnRefresh: true,
										StateFunc: func(v interface{}) string {
											json, _ := verify.LegacyPolicyNormalize(v)
											return json
										},
									},
								},
							},
						},
					},
				},
			},
			"authentication_method_type": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				ValidateDiagFunc: enum.Validate[types.AuthenticationMethodType](),
			},
		},
	}
}

func resourceApplicationAuthenticationMethodCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).SSOAdminClient(ctx)

	applicationARN := d.Get("application_arn").(string)
	authenticationMethodType := d.Get("authentication_method_type").(string)
	id := ApplicationAuthenticationMethodCreateResourceID(applicationARN, authenticationMethodType)

	input := &ssoadmin.PutApplicationAuthenticationMethodInput{
		ApplicationArn:           aws.String(applicationARN),
		AuthenticationMethod:     expandAuthenticationMethod(d.Get("authentication_method").([]interface{})),
		AuthenticationMethodType: types.AuthenticationMethodType(authenticationMethodType),
	}

	_, err := conn.PutApplicationAuthenticationMethod(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating SSO Application Authentication Method (%s): %s", id, err)
	}

	d.SetId(id)

	return append(diags, resourceApplicationAuthenticationMethodRead(ctx, d, meta)...)
}

func resourceApplicationAuthenticationMethodRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).SSOAdminClient(ctx)

	applicationARN, authenticationMethodType, err := ApplicationAuthenticationMethodParseResourceID(d.Id())
	if err != nil {
		return sdkdiag.AppendFromErr(diags, err)
	}

	output, err := FindApplicationAuthenticationMethodByMethodTypeAndApplicationARN(ctx, conn, applicationARN, authenticationMethodType)

	if !d.IsNewResource() && tfresource.NotFound(err) {
		log.Printf("[WARN] SSO Application Authentication Method (%s) not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading SSO Application Authentication Method (%s): %s", d.Id(), err)
	}

	d.Set("application_arn", applicationARN)
	d.Set("authentication_method", flattenAuthenticationMethod(output.AuthenticationMethod))
	d.Set("authentication_method_type", authenticationMethodType)

	return diags
}

func resourceApplicationAuthenticationMethodDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).SSOAdminClient(ctx)

	applicationARN, authenticationMethodType, err := ApplicationAuthenticationMethodParseResourceID(d.Id())
	if err != nil {
		return sdkdiag.AppendFromErr(diags, err)
	}

	log.Printf("[INFO] Deleting SSO Application Authentication Method: %s", d.Id())
	_, err = conn.DeleteApplicationAuthenticationMethod(ctx, &ssoadmin.DeleteApplicationAuthenticationMethodInput{
		ApplicationArn:           aws.String(applicationARN),
		AuthenticationMethodType: types.AuthenticationMethodType(authenticationMethodType),
	})

	if errs.IsA[*types.ResourceNotFoundException](err) {
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting SSO Application Authentication Method (%s): %s", d.Id(), err)
	}

	return diags
}

const applicationAuthenticationMethodIDSeparator = ","

func ApplicationAuthenticationMethodCreateResourceID(applicationARN, scope string) string {
	parts := []string{applicationARN, scope}
	id := strings.Join(parts, applicationAuthenticationMethodIDSeparator)

	return id
}

func ApplicationAuthenticationMethodParseResourceID(id string) (string, string, error) {
	parts := strings.Split(id, applicationAuthenticationMethodIDSeparator)

	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[0], parts[1], nil
	}

	return "", "", fmt.Errorf("unexpected format for ID (%[1]s), expected APPLICATION_ARN%[2]sAUTHENTICATION_METHOD_TYPE", id, applicationAuthenticationMethodIDSeparator)
}

func FindApplicationAuthenticationMethodByMethodTypeAndApplicationARN(ctx context.Context, conn *ssoadmin.Client, applicationARN, authenticationMethodType string) (*ssoadmin.GetApplicationAuthenticationMethodOutput, error) {
	input := &ssoadmin.GetApplicationAuthenticationMethodInput{
		ApplicationArn:           aws.String(applicationARN),
		AuthenticationMethodType: types.AuthenticationMethodType(authenticationMethodType),
	}

	output, err := conn.GetApplicationAuthenticationMethod(ctx, input)

	if errs.IsA[*types.ResourceNotFoundException](err) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: input,
		}
	}

	if err != nil {
		return nil, err
	}

	if output == nil {
		return nil, tfresource.NewEmptyResultError(input)
	}

	return output, nil
}

func expandAuthenticationMethod(tfMap []interface{}) *types.AuthenticationMethodMemberIam {
	apiObject := types.AuthenticationMethodMemberIam{}

	if len(tfMap) == 0 {
		return &apiObject

	}

	tfList, ok := tfMap[0].(map[string]interface{})
	if !ok {
		return &apiObject

	}

	if v, ok := tfList["iam"].([]interface{}); ok && len(v) > 0 {
		tfList, ok := v[0].(map[string]interface{})
		if !ok {
			return nil
		}

		if v, ok := tfList["actor_policy"]; ok {
			policy, _ := structure.NormalizeJsonString(v.(string))
			apiObject.Value.ActorPolicy = document.NewLazyDocument(policy)
		}
	}

	return &apiObject
}

func flattenAuthenticationMethod(apiObject types.AuthenticationMethod) []interface{} {
	if apiObject == nil {
		return nil
	}

	input := apiObject.(*types.AuthenticationMethodMemberIam)

	tfMap := map[string]interface{}{}

	if v := input.Value.ActorPolicy; v != nil {
		actorPolicy, _ := v.MarshalSmithyDocument()

		tfMap["iam"] = map[string]interface{}{
			"actor_policy": string(actorPolicy),
		}
	}

	return []interface{}{tfMap}
}
