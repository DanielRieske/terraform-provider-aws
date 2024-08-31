// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssoadmin

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin/document"
	awstypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/enum"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	intflex "github.com/hashicorp/terraform-provider-aws/internal/flex"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	"github.com/hashicorp/terraform-provider-aws/internal/framework/flex"
	fwtypes "github.com/hashicorp/terraform-provider-aws/internal/framework/types"
	"github.com/hashicorp/terraform-provider-aws/internal/json"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @FrameworkResource(name="Application Authentication Method")
func newResourceApplicationAuthenticationMethod(_ context.Context) (resource.ResourceWithConfigure, error) {
	return &resourceApplicationAuthenticationMethod{}, nil
}

const (
	ResNameApplicationAuthenticationMethod = "Application Authentication Method"

	applicationAuthenticationMethodIDPartCount = 2
)

type resourceApplicationAuthenticationMethod struct {
	framework.ResourceWithConfigure
}

func (r *resourceApplicationAuthenticationMethod) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "aws_ssoadmin_application_authentication_method"
}

func (r *resourceApplicationAuthenticationMethod) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"application_arn": schema.StringAttribute{
				CustomType: fwtypes.ARNType,
				Required:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"authentication_method_type": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					enum.FrameworkValidate[awstypes.AuthenticationMethodType](),
				},
			},
			names.AttrID: framework.IDAttribute(),
		},
		Blocks: map[string]schema.Block{
			"authentication_method": schema.ListNestedBlock{
				CustomType: fwtypes.NewListNestedObjectTypeOf[authenticationMethod](ctx),
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
				Validators: []validator.List{
					listvalidator.IsRequired(),
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Blocks: map[string]schema.Block{
						"iam": schema.ListNestedBlock{
							CustomType: fwtypes.NewListNestedObjectTypeOf[iam](ctx),
							Validators: []validator.List{
								listvalidator.SizeAtMost(1),
							},
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"actor_policy": schema.StringAttribute{
										CustomType: fwtypes.NewSmithyJSONType(ctx, document.NewLazyDocument),
										Required:   true,
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *resourceApplicationAuthenticationMethod) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	conn := r.Meta().SSOAdminClient(ctx)

	var plan resourceApplicationAuthenticationMethodData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input := &ssoadmin.PutApplicationAuthenticationMethodInput{}
	resp.Diagnostics.Append(flex.Expand(ctx, plan, input)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := conn.PutApplicationAuthenticationMethod(ctx, input)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.SSOAdmin, create.ErrActionCreating, ResNameApplicationAuthenticationMethod, plan.ApplicationARN.ValueString(), err),
			err.Error(),
		)
		return
	}

	idParts := []string{
		plan.ApplicationARN.ValueString(),
		plan.AuthenticationMethodType.ValueString(),
	}
	id, err := intflex.FlattenResourceId(idParts, applicationAuthenticationMethodIDPartCount, false)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.SSOAdmin, create.ErrActionCreating, ResNameApplicationAuthenticationMethod, plan.ApplicationARN.String(), err),
			err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(id)

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *resourceApplicationAuthenticationMethod) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	conn := r.Meta().SSOAdminClient(ctx)

	var state resourceApplicationAuthenticationMethodData
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	output, err := findApplicationAuthenticationMethodByMethodTypeAndApplicationARN(ctx, conn, state.ID.ValueString())
	if tfresource.NotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.SSOAdmin, create.ErrActionSetting, ResNameApplicationAuthenticationMethod, state.ID.ValueString(), err),
			err.Error(),
		)
		return
	}

	resp.Diagnostics.Append(flex.Flatten(ctx, output, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceApplicationAuthenticationMethod) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Np-op update
}

func (r *resourceApplicationAuthenticationMethod) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	conn := r.Meta().SSOAdminClient(ctx)

	var state resourceApplicationAuthenticationMethodData
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	parts, err := intflex.ExpandResourceId(state.ID.ValueString(), applicationAuthenticationMethodIDPartCount, false)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.SSOAdmin, create.ErrActionDeleting, ResNameApplicationAuthenticationMethod, state.ID.ValueString(), err),
			err.Error(),
		)
		return
	}

	input := &ssoadmin.DeleteApplicationAuthenticationMethodInput{
		ApplicationArn:           aws.String(parts[0]),
		AuthenticationMethodType: awstypes.AuthenticationMethodType(parts[1]),
	}

	_, err = conn.DeleteApplicationAuthenticationMethod(ctx, input)
	if err != nil {
		if errs.IsA[*awstypes.ResourceNotFoundException](err) {
			return
		}
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.SSOAdmin, create.ErrActionDeleting, ResNameTrustedTokenIssuer, state.ID.String(), err),
			err.Error(),
		)
		return
	}
}

func (r *resourceApplicationAuthenticationMethod) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root(names.AttrID), req, resp)
}

func findApplicationAuthenticationMethodByMethodTypeAndApplicationARN(ctx context.Context, conn *ssoadmin.Client, id string) (*awstypes.AuthenticationMethod, error) {
	parts, err := intflex.ExpandResourceId(id, applicationAuthenticationMethodIDPartCount, false)
	if err != nil {
		return nil, err
	}

	input := &ssoadmin.GetApplicationAuthenticationMethodInput{
		ApplicationArn:           aws.String(parts[0]),
		AuthenticationMethodType: awstypes.AuthenticationMethodType(parts[1]),
	}

	output, err := conn.GetApplicationAuthenticationMethod(ctx, input)

	if errs.IsA[*awstypes.ResourceNotFoundException](err) {
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

	return &output.AuthenticationMethod, nil
}

var (
	_ flex.Expander = authenticationMethod{}
	//_ flex.Flattener = &authenticationMethod{}
	_ flex.Expander = iam{}
)

func (m authenticationMethod) Expand(ctx context.Context) (result any, diags diag.Diagnostics) {
	switch {
	case !m.IAM.IsNull():
		var result awstypes.AuthenticationMethodMemberIam
		diags.Append(flex.Expand(ctx, m.IAM, &result.Value)...)
		if diags.HasError() {
			return nil, diags
		}
		return &result, diags
	}

	return nil, diags
}

func (m iam) Expand(ctx context.Context) (result any, diags diag.Diagnostics) {
	if m.ActorPolicy.IsNull() {
		return nil, diags
	}

	document, err := json.SmithyDocumentFromString(m.ActorPolicy.ValueString(), document.NewLazyDocument)
	if err != nil {
		return nil, diags
	}

	return &awstypes.IamAuthenticationMethod{
		ActorPolicy: document,
	}, diags
}

// func (m *authenticationMethod) Flatten(ctx context.Context, v any) (diags diag.Diagnostics) {
// 	switch t := v.(type) {
// 	case awstypes.AuthenticationMethodMemberIam:
// 		var model iam
// 		d := fwflex.Flatten(ctx, t.Value, &model)
// 		diags.Append(d...)
// 		if diags.HasError() {
// 			return diags
// 		}

// 		m.IAM = fwtypes.NewListNestedObjectValueOfPtrMust(ctx, &model)

// 		return diags
// 	}

// 	return diags
// }

type resourceApplicationAuthenticationMethodData struct {
	ApplicationARN           fwtypes.ARN                                           `tfsdk:"application_arn"`
	AuthenticationMethod     fwtypes.ListNestedObjectValueOf[authenticationMethod] `tfsdk:"authentication_method"`
	AuthenticationMethodType types.String                                          `tfsdk:"authentication_method_type"`
	ID                       types.String                                          `tfsdk:"id"`
}

type authenticationMethod struct {
	IAM fwtypes.ListNestedObjectValueOf[iam] `tfsdk:"iam"`
}

type iam struct {
	ActorPolicy fwtypes.SmithyJSON[document.Interface] `tfsdk:"actor_policy"`
}
