// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iot

import (
	"context"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iot"
	"github.com/hashicorp/aws-sdk-go-base/v2/awsv1shim/v2/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/id"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/retry"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-provider-aws/internal/conns"
	"github.com/hashicorp/terraform-provider-aws/internal/errs/sdkdiag"
	tftags "github.com/hashicorp/terraform-provider-aws/internal/tags"
	"github.com/hashicorp/terraform-provider-aws/internal/tfresource"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @SDKResource("aws_iot_software_package", name="Software Package")
// @Tags(identifierAttribute="package_arn")
func ResourceSoftwarePackage() *schema.Resource {
	return &schema.Resource{
		CreateWithoutTimeout: resourceSoftwarePackageCreate,
		ReadWithoutTimeout:   resourceSoftwarePackageRead,
		UpdateWithoutTimeout: resourceSoftwarePackageUpdate,
		DeleteWithoutTimeout: resourceSoftwarePackageDelete,
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},

		Schema: map[string]*schema.Schema{
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"package_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"package_arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
			names.AttrTags:    tftags.TagsSchema(),
			names.AttrTagsAll: tftags.TagsSchemaComputed(),
		},
		CustomizeDiff: verify.SetTagsDiff,
	}
}

func resourceSoftwarePackageCreate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).IoTConn(ctx)

	//out, err := conn.CreatePackageWithContext(ctx,

	input := &iot.CreatePackageInput{
		ClientToken: aws.String(id.UniqueId()),
		Description: aws.String(d.Get("description").(string)),
		PackageName: aws.String(d.Get("package_name").(string)),
		Tags:        convertIotTagsToMap(getTagsIn(ctx)),
	}

	out, err := conn.CreatePackageWithContext(ctx, input)

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "creating IoT Software Package: %s", err)
	}

	d.SetId(aws.StringValue(out.PackageName))
	d.Set("package_arn", out.PackageArn)

	return append(diags, resourcePolicyRead(ctx, d, meta)...)
}

func resourceSoftwarePackageRead(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).IoTConn(ctx)

	out, err := conn.GetPackageWithContext(ctx, &iot.GetPackageInput{
		PackageName: aws.String(d.Get("package_name").(string)),
	})

	if tfawserr.ErrCodeEquals(err, iot.ErrCodeResourceNotFoundException) {
		log.Printf("[WARN] IoT Software Package (%s) not found, removing from state", d.Id())
		d.SetId("")
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "reading IoT Software Package (%s): %s", d.Id(), err)
	}

	d.Set("description", out.Description)
	d.Set("package_name", out.PackageName)
	d.Set("package_arn", out.PackageArn)

	return diags
}

func resourceSoftwarePackageUpdate(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).IoTConn(ctx)

	if d.HasChange("description") || d.HasChange("package_name") {
		_, err := conn.UpdatePackageWithContext(ctx, &iot.UpdatePackageInput{
			ClientToken: aws.String(id.UniqueId()),
			Description: aws.String(d.Get("description").(string)),
			PackageName: aws.String(d.Get("package_name").(string)),
		})

		if err != nil {
			return sdkdiag.AppendErrorf(diags, "updating IoT Software Package (%s): %s", d.Id(), err)
		}
	}

	return append(diags, resourcePolicyRead(ctx, d, meta)...)
}

func resourceSoftwarePackageDelete(ctx context.Context, d *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	conn := meta.(*conns.AWSClient).IoTConn(ctx)

	_, err := conn.DeletePackageWithContext(ctx, &iot.DeletePackageInput{
		ClientToken: aws.String(id.UniqueId()),
		PackageName: aws.String(d.Get("package_name").(string)),
	})

	if tfawserr.ErrCodeEquals(err, iot.ErrCodeResourceNotFoundException) {
		return diags
	}

	if err != nil {
		return sdkdiag.AppendErrorf(diags, "deleting IoT Software Package (%s): %s", d.Id(), err)
	}

	return diags
}

func FindSoftwarePackageByName(ctx context.Context, conn *iot.IoT, name string) (*iot.GetPackageOutput, error) {

	output, err := conn.GetPackageWithContext(ctx, &iot.GetPackageInput{
		PackageName: aws.String(name),
	})

	if tfawserr.ErrCodeEquals(err, iot.ErrCodeResourceNotFoundException) {
		return nil, &retry.NotFoundError{
			LastError:   err,
			LastRequest: output,
		}
	}

	if err != nil {
		return nil, err
	}

	if output == nil {
		return nil, tfresource.NewEmptyResultError(output)
	}

	return output, nil
}

func convertIotTagsToMap(tags []*iot.Tag) map[string]*string {
	result := make(map[string]*string)

	for key := range tags {
		result[*tags[key].Key] = tags[key].Value
	}
	return result
}
