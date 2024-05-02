// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package verifiedpermissions

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/verifiedpermissions"
	awstypes "github.com/aws/aws-sdk-go-v2/service/verifiedpermissions/types"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/id"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-provider-aws/internal/create"
	"github.com/hashicorp/terraform-provider-aws/internal/errs"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	"github.com/hashicorp/terraform-provider-aws/internal/framework/flex"
	fwtypes "github.com/hashicorp/terraform-provider-aws/internal/framework/types"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @FrameworkResource(name="Identity Source")
func newResourceIdentitySource(context.Context) (resource.ResourceWithConfigure, error) {
	r := &resourceIdentitySource{}

	return r, nil
}

const (
	ResNameIdentitySource = "Policy Store"
)

type resourceIdentitySource struct {
	framework.ResourceWithConfigure
}

func (r *resourceIdentitySource) Metadata(_ context.Context, request resource.MetadataRequest, response *resource.MetadataResponse) {
	response.TypeName = "aws_verifiedpermissions_identity_source"
}

func (r *resourceIdentitySource) Schema(ctx context.Context, request resource.SchemaRequest, response *resource.SchemaResponse) {
	s := schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": framework.IDAttribute(),
			"policy_store_id": schema.StringAttribute{
				Required: true,
			},
			"principal_entity_type": schema.StringAttribute{
				Optional: true,
			},
		},
		Blocks: map[string]schema.Block{
			"configuration": schema.ListNestedBlock{
				Validators: []validator.List{
					listvalidator.IsRequired(),
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Blocks: map[string]schema.Block{
						"cognito_user_pool_configuration": schema.ListNestedBlock{
							Validators: []validator.List{
								listvalidator.SizeAtMost(1),
							},
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"user_pool_arn": schema.StringAttribute{
										Required: true,
									},
									"client_ids": schema.ListAttribute{
										Required:    true,
										CustomType:  fwtypes.ListOfStringType,
										ElementType: types.StringType,
									},
								},
								Blocks: map[string]schema.Block{
									"group_configuration": schema.ListNestedBlock{
										Validators: []validator.List{
											listvalidator.SizeAtMost(1),
										},
										NestedObject: schema.NestedBlockObject{
											Attributes: map[string]schema.Attribute{
												"group_entity_type": schema.StringAttribute{
													Optional: true,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	response.Schema = s
}

func (r *resourceIdentitySource) Create(ctx context.Context, request resource.CreateRequest, resp *resource.CreateResponse) {
	conn := r.Meta().VerifiedPermissionsClient(ctx)

	var plan resourceIdentitySourceData
	resp.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	input := &verifiedpermissions.CreateIdentitySourceInput{
		ClientToken:   aws.String(id.UniqueId()),
		PolicyStoreId: plan.PolicyStoreId.ValueStringPointer(),
	}

	if !plan.PrincipalEntityType.IsNull() {
		input.PrincipalEntityType = aws.String(plan.PrincipalEntityType.ValueString())
	}

	if !plan.Configuration.IsNull() {
		var tfList []ConfigurationData
		resp.Diagnostics.Append(plan.Configuration.ElementsAs(ctx, &tfList, false)...)
		if resp.Diagnostics.HasError() {
			return
		}

		identitySourceConfiguration, d := expandIdentitySourceConfiguration(ctx, tfList)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		input.Configuration = identitySourceConfiguration
	}

	output, err := conn.CreateIdentitySource(ctx, input)

	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.VerifiedPermissions, create.ErrActionCreating, ResNameIdentitySource, plan.PolicyStoreId.ValueString(), err),
			err.Error(),
		)
		return
	}

	state := plan
	state.ID = flex.StringToFramework(ctx, output.IdentitySourceId)

	resp.Diagnostics.Append(flex.Flatten(ctx, output, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceIdentitySource) Read(ctx context.Context, request resource.ReadRequest, resp *resource.ReadResponse) {
	conn := r.Meta().VerifiedPermissionsClient(ctx)

	var state resourceIdentitySourceData
	resp.Diagnostics.Append(request.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	output, err := findIdentitySourceByID(ctx, conn, state.ID.ValueString())

	if tfresource.NotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.VerifiedPermissions, create.ErrActionReading, ResNameIdentitySource, state.PolicyStoreId.ValueString(), err),
			err.Error(),
		)
		return
	}

	state.ID = flex.StringToFramework(ctx, output.IdentitySourceId)
	state.PolicyStoreId = flex.StringToFramework(ctx, output.IdentitySourceId)
	state.PrincipalEntityType = flex.StringToFramework(ctx, output.PrincipalEntityType)

	configurationData, d := flattenIdentitySourceConfiguration(ctx, output.Configuration)
	resp.Diagnostics.Append(d...)
	state.Configuration = configurationData

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceIdentitySource) Update(ctx context.Context, request resource.UpdateRequest, resp *resource.UpdateResponse) {
	conn := r.Meta().VerifiedPermissionsClient(ctx)

	var state, plan resourceIdentitySourceData
	resp.Diagnostics.Append(request.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(request.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if !plan.Configuration.Equal(state.Configuration) || !plan.PrincipalEntityType.Equal(state.PrincipalEntityType) || !plan.PolicyStoreId.Equal(state.PolicyStoreId) {
		input := &verifiedpermissions.UpdateIdentitySourceInput{}

		if !plan.Configuration.IsNull() {
			var tfList []ConfigurationData
			resp.Diagnostics.Append(plan.Configuration.ElementsAs(ctx, &tfList, false)...)
			if resp.Diagnostics.HasError() {
				return
			}

			identitySourceConfiguration, d := expandIdentitySourceUpdateConfiguration(ctx, tfList)
			resp.Diagnostics.Append(d...)
			if resp.Diagnostics.HasError() {
				return
			}
			input.UpdateConfiguration = identitySourceConfiguration
		}

		if !plan.PolicyStoreId.IsNull() {
			input.PolicyStoreId = plan.PolicyStoreId.ValueStringPointer()
		}

		if !plan.PrincipalEntityType.IsNull() {
			input.PrincipalEntityType = plan.PrincipalEntityType.ValueStringPointer()
		}

		_, err := conn.UpdateIdentitySource(ctx, input)
		if err != nil {
			resp.Diagnostics.AddError(
				create.ProblemStandardMessage(names.VerifiedPermissions, create.ErrActionUpdating, ResNameIdentitySource, plan.ID.String(), err),
				err.Error(),
			)
			return
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *resourceIdentitySource) Delete(ctx context.Context, request resource.DeleteRequest, response *resource.DeleteResponse) {
	conn := r.Meta().VerifiedPermissionsClient(ctx)
	var state resourceIdentitySourceData

	response.Diagnostics.Append(request.State.Get(ctx, &state)...)

	if response.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "deleting Verified Permissions Policy Store", map[string]interface{}{
		"id": state.ID.ValueString(),
	})

	input := &verifiedpermissions.DeleteIdentitySourceInput{
		IdentitySourceId: flex.StringFromFramework(ctx, state.ID),
	}

	_, err := conn.DeleteIdentitySource(ctx, input)

	if errs.IsA[*awstypes.ResourceNotFoundException](err) {
		return
	}

	if err != nil {
		response.Diagnostics.AddError(
			create.ProblemStandardMessage(names.VerifiedPermissions, create.ErrActionDeleting, ResNameIdentitySource, state.ID.String(), err),
			err.Error(),
		)
		return
	}
}

func (r *resourceIdentitySource) ImportState(ctx context.Context, request resource.ImportStateRequest, response *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), request, response)
}

func findIdentitySourceByID(ctx context.Context, conn *verifiedpermissions.Client, id string) (*verifiedpermissions.GetIdentitySourceOutput, error) {
	in := &verifiedpermissions.GetIdentitySourceInput{
		IdentitySourceId: aws.String(id),
	}

	out, err := conn.GetIdentitySource(ctx, in)
	if errs.IsA[*awstypes.ResourceNotFoundException](err) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: in,
		}
	}
	if err != nil {
		return nil, err
	}

	if out == nil || out.IdentitySourceId == nil {
		return nil, tfresource.NewEmptyResultError(in)
	}

	return out, nil
}

func expandIdentitySourceConfiguration(ctx context.Context, tfList []ConfigurationData) (awstypes.Configuration, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(tfList) == 0 {
		return nil, diags
	}
	tfObj := tfList[0]

	var configurationDetailData []ConfigurationDetailData
	diags.Append(tfObj.CognitoUserPoolConfiguration.ElementsAs(ctx, &configurationDetailData, false)...)

	cognitoUserPoolConfiguration, d := expandCognitoUserPoolConfiguration(ctx, configurationDetailData)
	diags.Append(d...)

	apiObject := &awstypes.ConfigurationMemberCognitoUserPoolConfiguration{
		Value: *cognitoUserPoolConfiguration,
	}

	return apiObject, diags
}

func expandCognitoUserPoolConfiguration(ctx context.Context, tfList []ConfigurationDetailData) (*awstypes.CognitoUserPoolConfiguration, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(tfList) == 0 {
		return nil, diags
	}

	tfObj := tfList[0]

	var groupConfigurationData []GroupConfigurationData
	diags.Append(tfObj.GroupConfiguration.ElementsAs(ctx, &groupConfigurationData, false)...)

	apiObject := &awstypes.CognitoUserPoolConfiguration{
		UserPoolArn:        tfObj.UserPoolArn.ValueStringPointer(),
		ClientIds:          flex.ExpandFrameworkStringValueList(ctx, tfObj.ClientIds),
		GroupConfiguration: expandGroupConfiguration(groupConfigurationData),
	}

	return apiObject, diags
}

func expandGroupConfiguration(tfList []GroupConfigurationData) *awstypes.CognitoGroupConfiguration {
	if len(tfList) == 0 {
		return nil
	}

	tfObj := tfList[0]

	apiObject := &awstypes.CognitoGroupConfiguration{
		GroupEntityType: tfObj.GroupEntityType.ValueStringPointer(),
	}

	return apiObject
}

func expandIdentitySourceUpdateConfiguration(ctx context.Context, tfList []ConfigurationData) (awstypes.UpdateConfiguration, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(tfList) == 0 {
		return nil, diags
	}
	tfObj := tfList[0]

	var configurationDetailData []ConfigurationDetailData
	diags.Append(tfObj.CognitoUserPoolConfiguration.ElementsAs(ctx, &configurationDetailData, false)...)

	cognitoUserPoolConfiguration, d := expandCognitoUserPoolUpdateConfiguration(ctx, configurationDetailData)
	diags.Append(d...)

	apiObject := &awstypes.UpdateConfigurationMemberCognitoUserPoolConfiguration{
		Value: *cognitoUserPoolConfiguration,
	}

	return apiObject, diags
}

func expandCognitoUserPoolUpdateConfiguration(ctx context.Context, tfList []ConfigurationDetailData) (*awstypes.UpdateCognitoUserPoolConfiguration, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(tfList) == 0 {
		return nil, diags
	}

	tfObj := tfList[0]

	var groupConfigurationData []GroupConfigurationData
	diags.Append(tfObj.GroupConfiguration.ElementsAs(ctx, &groupConfigurationData, false)...)

	apiObject := &awstypes.UpdateCognitoUserPoolConfiguration{
		UserPoolArn:        tfObj.UserPoolArn.ValueStringPointer(),
		ClientIds:          flex.ExpandFrameworkStringValueList(ctx, tfObj.ClientIds),
		GroupConfiguration: expandGroupUpdateConfiguration(groupConfigurationData),
	}

	return apiObject, diags
}

func expandGroupUpdateConfiguration(tfList []GroupConfigurationData) *awstypes.UpdateCognitoGroupConfiguration {
	if len(tfList) == 0 {
		return nil
	}

	tfObj := tfList[0]

	apiObject := &awstypes.UpdateCognitoGroupConfiguration{
		GroupEntityType: tfObj.GroupEntityType.ValueStringPointer(),
	}

	return apiObject
}

func flattenIdentitySourceConfiguration(ctx context.Context, apiObject awstypes.ConfigurationDetail) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	elemType := types.ObjectType{AttrTypes: ConfigurationAttrTypes}

	if apiObject == nil {
		return types.ListNull(elemType), diags
	}

	obj := map[string]attr.Value{}

	switch v := apiObject.(type) {
	case *awstypes.ConfigurationDetailMemberCognitoUserPoolConfiguration:
		oidcJWTConfiguration, d := flattenCognitoUserPoolConfiguration(ctx, &v.Value)
		obj["cognito_user_pool_configuration"] = oidcJWTConfiguration
		diags.Append(d...)
	default:
		log.Println("union is nil or unknown type")
	}

	objVal, d := types.ObjectValue(ConfigurationAttrTypes, obj)
	diags.Append(d...)

	listVal, d := types.ListValue(elemType, []attr.Value{objVal})
	diags.Append(d...)

	return listVal, diags
}

func flattenCognitoUserPoolConfiguration(ctx context.Context, apiObject *awstypes.CognitoUserPoolConfigurationDetail) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	elemType := types.ObjectType{AttrTypes: ConfigurationDetailAttrTypes}

	if apiObject == nil {
		return types.ListNull(elemType), diags
	}

	obj := map[string]attr.Value{
		"client_ids":          flex.FlattenFrameworkStringValueList(ctx, apiObject.ClientIds),
		"user_pool_arn":       flex.StringToFramework(ctx, apiObject.UserPoolArn),
		"group_configuration": flattenGroupConfiguration(ctx, apiObject.GroupConfiguration),
	}

	objVal, d := types.ObjectValue(ConfigurationDetailAttrTypes, obj)
	diags.Append(d...)

	listVal, d := types.ListValue(elemType, []attr.Value{objVal})
	diags.Append(d...)

	return listVal, diags
}

func flattenGroupConfiguration(ctx context.Context, apiObject *awstypes.CognitoGroupConfigurationDetail) types.List {
	var diags diag.Diagnostics
	elemType := types.ObjectType{AttrTypes: GroupConfigurationAttrTypes}

	if apiObject == nil {
		return types.ListNull(elemType)
	}

	obj := map[string]attr.Value{
		"group_entity_type": flex.StringToFramework(ctx, apiObject.GroupEntityType),
	}

	objVal, d := types.ObjectValue(GroupConfigurationAttrTypes, obj)
	diags.Append(d...)

	listVal, d := types.ListValue(elemType, []attr.Value{objVal})
	diags.Append(d...)

	return listVal
}

type resourceIdentitySourceData struct {
	Configuration       types.List   `tfsdk:"configuration"`
	ID                  types.String `tfsdk:"id"`
	PolicyStoreId       types.String `tfsdk:"policy_store_id"`
	PrincipalEntityType types.String `tfsdk:"principal_entity_type"`
}

type ConfigurationData struct {
	CognitoUserPoolConfiguration types.List `tfsdk:"cognito_user_pool_configuration"`
}

type ConfigurationDetailData struct {
	ClientIds          types.List   `tfsdk:"client_ids"`
	UserPoolArn        types.String `tfsdk:"user_pool_arn"`
	GroupConfiguration types.List   `tfsdk:"group_configuration"`
}

type GroupConfigurationData struct {
	GroupEntityType types.String `tfsdk:"group_entity_type"`
}

var ConfigurationAttrTypes = map[string]attr.Type{
	"cognito_user_pool_configuration": types.ListType{ElemType: types.ObjectType{AttrTypes: ConfigurationDetailAttrTypes}},
}

var ConfigurationDetailAttrTypes = map[string]attr.Type{
	"client_ids":          types.ListType{ElemType: types.ListType{ElemType: types.StringType}},
	"user_pool_arn":       types.StringType,
	"group_configuration": types.ListType{ElemType: types.ObjectType{AttrTypes: GroupConfigurationAttrTypes}},
}

var GroupConfigurationAttrTypes = map[string]attr.Type{
	"group_entity_type": types.StringType,
}
