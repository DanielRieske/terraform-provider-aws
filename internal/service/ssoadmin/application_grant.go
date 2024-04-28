// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package ssoadmin

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	awstypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @FrameworkResource(name="Application Grant")
func newResourceApplicationGrant(_ context.Context) (resource.ResourceWithConfigure, error) {
	return &resourceApplicationGrant{}, nil
}

const (
	ResNameApplicationGrant = "Application Grant"

	applicationGrantIDPartCount = 2
)

type resourceApplicationGrant struct {
	framework.ResourceWithConfigure
}

func (r *resourceApplicationGrant) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "aws_ssoadmin_application_grant"
}

func (r *resourceApplicationGrant) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"application_arn": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"id": framework.IDAttribute(),
			"grant_type": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Validators: []validator.String{
					enum.FrameworkValidate[awstypes.GrantType](),
				},
			},
		},
		Blocks: map[string]schema.Block{
			"grant": schema.ListNestedBlock{
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
					listvalidator.IsRequired(),
				},
				NestedObject: schema.NestedBlockObject{
					Blocks: map[string]schema.Block{
						"authorization_code": schema.ListNestedBlock{
							Validators: []validator.List{
								listvalidator.SizeAtMost(1),
								listvalidator.ExactlyOneOf(
									path.MatchRelative().AtParent().AtName("authorization_code"),
									path.MatchRelative().AtParent().AtName("jwt_bearer"),
									path.MatchRelative().AtParent().AtName("refresh_token"),
									path.MatchRelative().AtParent().AtName("token_exchange"),
								),
							},
							NestedObject: schema.NestedBlockObject{
								Attributes: map[string]schema.Attribute{
									"redirect_uris": schema.ListAttribute{
										ElementType: types.StringType,
										Optional:    true,
									},
								},
							},
						},
						"jwt_bearer": schema.ListNestedBlock{
							Validators: []validator.List{
								listvalidator.SizeAtMost(1),
								listvalidator.ExactlyOneOf(
									path.MatchRelative().AtParent().AtName("authorization_code"),
									path.MatchRelative().AtParent().AtName("jwt_bearer"),
									path.MatchRelative().AtParent().AtName("refresh_token"),
									path.MatchRelative().AtParent().AtName("token_exchange"),
								),
							},
							NestedObject: schema.NestedBlockObject{
								Blocks: map[string]schema.Block{
									"authorized_token_issuers": schema.SetNestedBlock{
										Validators: []validator.Set{
											setvalidator.SizeAtLeast(1),
											setvalidator.SizeAtMost(10),
										},
										NestedObject: schema.NestedBlockObject{
											Attributes: map[string]schema.Attribute{
												"authorized_audiences": schema.ListAttribute{
													ElementType: types.StringType,
													Optional:    true,
												},
												"trusted_token_issuer_arn": schema.StringAttribute{
													Optional: true,
												},
											},
										},
									},
								},
							},
						},
						"refresh_token": schema.ListNestedBlock{
							Validators: []validator.List{
								listvalidator.SizeAtMost(1),
								listvalidator.ExactlyOneOf(
									path.MatchRelative().AtParent().AtName("authorization_code"),
									path.MatchRelative().AtParent().AtName("jwt_bearer"),
									path.MatchRelative().AtParent().AtName("refresh_token"),
									path.MatchRelative().AtParent().AtName("token_exchange"),
								),
							},
						},
						"token_exchange": schema.ListNestedBlock{
							Validators: []validator.List{
								listvalidator.SizeAtMost(1),
								listvalidator.ExactlyOneOf(
									path.MatchRelative().AtParent().AtName("authorization_code"),
									path.MatchRelative().AtParent().AtName("jwt_bearer"),
									path.MatchRelative().AtParent().AtName("refresh_token"),
									path.MatchRelative().AtParent().AtName("token_exchange"),
								),
							},
						},
					},
				},
			},
		},
	}
}

func (r *resourceApplicationGrant) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	conn := r.Meta().SSOAdminClient(ctx)

	var plan resourceApplicationGrantData
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	applicationARN := plan.ApplicationARN.ValueString()
	grantType := plan.GrantType.ValueString()

	idParts := []string{
		applicationARN,
		grantType,
	}
	id, _ := intflex.FlattenResourceId(idParts, applicationGrantIDPartCount, false)
	plan.ID = types.StringValue(id)

	in := &ssoadmin.PutApplicationGrantInput{
		ApplicationArn: aws.String(applicationARN),
		GrantType:      awstypes.GrantType(grantType),
	}

	var tfList []resourceGrantData
	resp.Diagnostics.Append(plan.Grant.ElementsAs(ctx, &tfList, false)...)
	if resp.Diagnostics.HasError() {
		return
	}

	grant, d := expandGrant(ctx, tfList)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}

	in.Grant = grant

	_, err := conn.PutApplicationGrant(ctx, in)
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.SSOAdmin, create.ErrActionCreating, ResNameApplicationGrant, plan.ApplicationARN.String(), err),
			err.Error(),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceApplicationGrant) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	conn := r.Meta().SSOAdminClient(ctx)

	fmt.Println("Got Here")
	var state resourceApplicationGrantData
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	out, err := findApplicationGrantByID(ctx, conn, state.ID.ValueString())
	if tfresource.NotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.SSOAdmin, create.ErrActionSetting, ResNameApplicationGrant, state.ID.String(), err),
			err.Error(),
		)
		return
	}

	id, _ := intflex.ExpandResourceId(state.ID.String(), applicationGrantIDPartCount, false)

	state.ApplicationARN = flex.StringValueToFramework(ctx, id[0])
	state.GrantType = flex.StringValueToFramework(ctx, id[1])

	grant, d := flattenGrant(ctx, out.Grant)
	resp.Diagnostics.Append(d...)
	state.Grant = grant

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceApplicationGrant) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Np-op update
}

func (r *resourceApplicationGrant) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	conn := r.Meta().SSOAdminClient(ctx)

	var state resourceApplicationGrantData
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	in := &ssoadmin.DeleteApplicationGrantInput{
		ApplicationArn: aws.String(state.ApplicationARN.ValueString()),
		GrantType:      awstypes.GrantType(state.GrantType.ValueString()),
	}

	_, err := conn.DeleteApplicationGrant(ctx, in)
	if err != nil {
		if errs.IsA[*awstypes.ResourceNotFoundException](err) {
			return
		}
		resp.Diagnostics.AddError(
			create.ProblemStandardMessage(names.SSOAdmin, create.ErrActionDeleting, ResNameApplicationGrant, state.ID.String(), err),
			err.Error(),
		)
		return
	}
}

func (r *resourceApplicationGrant) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func findApplicationGrantByID(ctx context.Context, conn *ssoadmin.Client, id string) (*ssoadmin.GetApplicationGrantOutput, error) {
	parts, err := intflex.ExpandResourceId(id, applicationGrantIDPartCount, false)
	if err != nil {
		return nil, err
	}

	in := &ssoadmin.GetApplicationGrantInput{
		ApplicationArn: aws.String(parts[0]),
		GrantType:      awstypes.GrantType(parts[1]),
	}

	out, err := conn.GetApplicationGrant(ctx, in)
	if err != nil {
		if errs.IsA[*awstypes.ResourceNotFoundException](err) {
			return nil, &retry.NotFoundError{
				LastError:   err,
				LastRequest: in,
			}
		}

		return nil, err
	}

	if out == nil {
		return nil, tfresource.NewEmptyResultError(in)
	}

	return out, nil
}

func expandGrant(ctx context.Context, tfList []resourceGrantData) (awstypes.Grant, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(tfList) == 0 {
		return nil, diags
	}
	tfObj := tfList[0]

	if !tfObj.AuthorizationCode.IsNull() {
		var resourceGrantApplicationCodeData []resourceGrantApplicationCodeData
		diags.Append(tfObj.AuthorizationCode.ElementsAs(ctx, &resourceGrantApplicationCodeData, false)...)

		apiObject := &awstypes.GrantMemberAuthorizationCode{
			Value: *expandApplicationCode(ctx, resourceGrantApplicationCodeData),
		}

		return apiObject, diags
	}

	if !tfObj.JwtBearer.IsNull() {
		var resourceGrantJwtBearerData []resourceGrantJwtBearerData
		diags.Append(tfObj.JwtBearer.ElementsAs(ctx, &resourceGrantJwtBearerData, false)...)

		out, d := expandJwtBearer(ctx, resourceGrantJwtBearerData)
		diags.Append(d...)

		apiObject := &awstypes.GrantMemberJwtBearer{
			Value: *out,
		}
		return apiObject, diags
	}

	if !tfObj.RefreshToken.IsNull() {
		apiObject := &awstypes.GrantMemberRefreshToken{
			Value: awstypes.RefreshTokenGrant{},
		}
		return apiObject, diags
	}

	if !tfObj.TokenExchange.IsNull() {
		apiObject := &awstypes.GrantMemberTokenExchange{
			Value: awstypes.TokenExchangeGrant{},
		}
		return apiObject, diags
	}

	return nil, diags
}

func expandApplicationCode(ctx context.Context, tfList []resourceGrantApplicationCodeData) *awstypes.AuthorizationCodeGrant {
	if len(tfList) == 0 {
		return nil
	}

	tfObj := tfList[0]

	apiObject := &awstypes.AuthorizationCodeGrant{
		RedirectUris: flex.ExpandFrameworkStringValueList(ctx, tfObj.RedirectUris),
	}
	return apiObject
}

func expandJwtBearer(ctx context.Context, tfList []resourceGrantJwtBearerData) (*awstypes.JwtBearerGrant, diag.Diagnostics) {
	var diags diag.Diagnostics

	if len(tfList) == 0 {
		return nil, diags
	}

	tfObj := tfList[0]

	var resourceGrantJwtBearerAuthorizedTokenIssuerData []resourceGrantJwtBearerAuthorizedTokenIssuerData
	diags.Append(tfObj.AuthorizedTokenIssuers.ElementsAs(ctx, &resourceGrantJwtBearerAuthorizedTokenIssuerData, false)...)

	apiObject := &awstypes.JwtBearerGrant{
		AuthorizedTokenIssuers: expandAuthorizedTokenIssuers(ctx, resourceGrantJwtBearerAuthorizedTokenIssuerData),
	}

	return apiObject, diags
}

func expandAuthorizedTokenIssuers(ctx context.Context, tfList []resourceGrantJwtBearerAuthorizedTokenIssuerData) []awstypes.AuthorizedTokenIssuer {
	if len(tfList) == 0 {
		return nil
	}

	var apiObjects []awstypes.AuthorizedTokenIssuer

	for _, tokenIssuer := range tfList {
		apiObject := awstypes.AuthorizedTokenIssuer{
			AuthorizedAudiences:   flex.ExpandFrameworkStringValueList(ctx, tokenIssuer.AuthorizedAudiences),
			TrustedTokenIssuerArn: flex.StringFromFramework(ctx, tokenIssuer.TrustedTokenIssuerArn),
		}
		apiObjects = append(apiObjects, apiObject)
	}
	return apiObjects
}

func flattenGrant(ctx context.Context, apiObject awstypes.Grant) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	elemType := types.ObjectType{AttrTypes: GrantAttrTypes}

	if apiObject == nil {
		return types.ListNull(elemType), diags
	}

	obj := map[string]attr.Value{
		"authorization_code": types.ListNull(types.ObjectType{AttrTypes: AuthorizationCodeAttrTypes}),
		"jwt_bearer":         types.ListNull(types.ObjectType{AttrTypes: JwtBearerAttrTypes}),
		"refresh_token":      types.ListNull(types.ObjectType{AttrTypes: RefreshTokenAttrTypes}),
		"token_exchange":     types.ListNull(types.ObjectType{AttrTypes: TokenExchangeAttrTypes}),
	}

	switch v := apiObject.(type) {
	case *awstypes.GrantMemberAuthorizationCode:
		authorizationCode, d := flattenAuthorizationCode(ctx, &v.Value)
		obj["authorization_code"] = authorizationCode
		diags.Append(d...)
	case *awstypes.GrantMemberJwtBearer:
		jwtBearer, d := flattenJwtBearer(ctx, &v.Value)
		obj["jwt_bearer"] = jwtBearer
		diags.Append(d...)
	case *awstypes.GrantMemberRefreshToken:
		obj["refresh_token"] = types.ListNull(types.ObjectType{AttrTypes: RefreshTokenAttrTypes})
	case *awstypes.GrantMemberTokenExchange:
		obj["token_exchange"] = types.ListNull(types.ObjectType{AttrTypes: TokenExchangeAttrTypes})
	default:
		log.Println("union is nil or unknown type")
	}

	objVal, d := types.ObjectValue(GrantAttrTypes, obj)
	diags.Append(d...)

	listVal, d := types.ListValue(elemType, []attr.Value{objVal})
	diags.Append(d...)

	return listVal, diags
}

func flattenAuthorizationCode(ctx context.Context, apiObject *awstypes.AuthorizationCodeGrant) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	elemType := types.ObjectType{AttrTypes: AuthorizationCodeAttrTypes}

	if apiObject == nil {
		return types.ListNull(elemType), diags
	}

	obj := map[string]attr.Value{
		"redirect_uris": flex.FlattenFrameworkStringValueList(ctx, apiObject.RedirectUris),
	}

	objVal, d := types.ObjectValue(AuthorizationCodeAttrTypes, obj)
	diags.Append(d...)

	listVal, d := types.ListValue(elemType, []attr.Value{objVal})
	diags.Append(d...)

	return listVal, diags
}

func flattenJwtBearer(ctx context.Context, apiObject *awstypes.JwtBearerGrant) (types.List, diag.Diagnostics) {
	var diags diag.Diagnostics
	elemType := types.ObjectType{AttrTypes: JwtBearerAttrTypes}

	if apiObject == nil {
		return types.ListNull(elemType), diags
	}

	issuers, d := flattenJwtBearerAuthorizedTokenIssuers(ctx, apiObject.AuthorizedTokenIssuers)
	diags.Append(d...)

	obj := map[string]attr.Value{
		"authorized_token_issuers": issuers,
	}

	objVal, d := types.ObjectValue(JwtBearerAttrTypes, obj)
	diags.Append(d...)

	listVal, d := types.ListValue(elemType, []attr.Value{objVal})
	diags.Append(d...)

	return listVal, diags
}

func flattenJwtBearerAuthorizedTokenIssuers(ctx context.Context, apiObject []awstypes.AuthorizedTokenIssuer) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics
	elemType := types.ObjectType{AttrTypes: JwtBearerAuthorizedTokenIssuerAttrTypes}

	if apiObject == nil {
		return types.SetNull(elemType), diags
	}

	elems := []attr.Value{}

	for _, object := range apiObject {
		obj := map[string]attr.Value{
			"authorized_audiences":     flex.FlattenFrameworkStringValueList(ctx, object.AuthorizedAudiences),
			"trusted_token_issuer_arn": flex.StringToFramework(ctx, object.TrustedTokenIssuerArn),
		}

		objVal, d := types.ObjectValue(JwtBearerAuthorizedTokenIssuerAttrTypes, obj)
		diags.Append(d...)

		elems = append(elems, objVal)
	}

	setVal, d := types.SetValue(elemType, elems)
	diags.Append(d...)

	return setVal, diags
}

type resourceApplicationGrantData struct {
	ApplicationARN types.String `tfsdk:"application_arn"`
	ID             types.String `tfsdk:"id"`
	Grant          types.List   `tfsdk:"grant"`
	GrantType      types.String `tfsdk:"grant_type"`
}

type resourceGrantData struct {
	AuthorizationCode types.List `tfsdk:"authorization_code"`
	JwtBearer         types.List `tfsdk:"jwt_bearer"`
	RefreshToken      types.List `tfsdk:"refresh_token"`
	TokenExchange     types.List `tfsdk:"token_exchange"`
}

type resourceGrantApplicationCodeData struct {
	RedirectUris types.List `tfsdk:"redirect_uris"`
}

type resourceGrantJwtBearerData struct {
	AuthorizedTokenIssuers types.Set `tfsdk:"authorized_token_issuers"`
}

type resourceGrantJwtBearerAuthorizedTokenIssuerData struct {
	AuthorizedAudiences   types.List   `tfsdk:"authorized_audiences"`
	TrustedTokenIssuerArn types.String `tfsdk:"trusted_token_issuer_arn"`
}

var GrantAttrTypes = map[string]attr.Type{
	"authorization_code": types.ListType{ElemType: types.ObjectType{AttrTypes: AuthorizationCodeAttrTypes}},
	"jwt_bearer":         types.ListType{ElemType: types.ObjectType{AttrTypes: JwtBearerAttrTypes}},
	"refresh_token":      types.ListType{ElemType: types.ObjectType{AttrTypes: RefreshTokenAttrTypes}},
	"token_exchange":     types.ListType{ElemType: types.ObjectType{AttrTypes: TokenExchangeAttrTypes}},
}

var AuthorizationCodeAttrTypes = map[string]attr.Type{
	"redirect_uris": types.ListType{ElemType: types.StringType},
}

var JwtBearerAttrTypes = map[string]attr.Type{
	"authorized_token_issuers": types.SetType{ElemType: types.ObjectType{AttrTypes: JwtBearerAuthorizedTokenIssuerAttrTypes}},
}

var JwtBearerAuthorizedTokenIssuerAttrTypes = map[string]attr.Type{
	"authorized_audiences":     types.ListType{ElemType: types.StringType},
	"trusted_token_issuer_arn": types.StringType,
}

var RefreshTokenAttrTypes = map[string]attr.Type{}

var TokenExchangeAttrTypes = map[string]attr.Type{}
