// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/francis-fisher/terraform-provider-sagemcom-fast-5598/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/action"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = &SagemcomProvider{}
var _ provider.ProviderWithFunctions = &SagemcomProvider{}
var _ provider.ProviderWithEphemeralResources = &SagemcomProvider{}
var _ provider.ProviderWithActions = &SagemcomProvider{}

type SagemcomProvider struct {
	version string
}

type SagemcomProviderModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`
}

func (p *SagemcomProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "sagemcom"
	resp.Version = p.version
}

func (p *SagemcomProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The Sagemcom F@st router provider uses the router's backend REST API to configure the router.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "The IP address or URL of the Sagemcom router REST API.",
				Required:            true,
			},
			"username": schema.StringAttribute{
				MarkdownDescription: "The username for router administration. Defaults to `admin`.",
				Optional:            true,
			},
			"password": schema.StringAttribute{
				MarkdownDescription: "The password for router administration.",
				Required:            true,
				Sensitive:           true,
			},
		},
	}
}

func (p *SagemcomProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data SagemcomProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if data.Endpoint.IsNull() || data.Password.IsNull() {
		return
	}

	endpoint := data.Endpoint.ValueString()
	password := data.Password.ValueString()

	username := "admin"
	if !data.Username.IsNull() {
		username = data.Username.ValueString()
	}

	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "http://" + endpoint
	}

	c, err := client.NewClient(endpoint, username, password)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Initialize Client",
			fmt.Sprintf("Could not create the Sagemcom API client: %s", err.Error()),
		)
		return
	}

	err = c.Login(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to Authenticate",
			fmt.Sprintf("Login to Sagemcom router failed: %s", err.Error()),
		)
		return
	}

	resp.DataSourceData = c
	resp.ResourceData = c
}

func (p *SagemcomProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewDHCPReservedAddressResource,
	}
}

func (p *SagemcomProvider) EphemeralResources(ctx context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{}
}

func (p *SagemcomProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *SagemcomProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}

func (p *SagemcomProvider) Actions(ctx context.Context) []func() action.Action {
	return []func() action.Action{}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &SagemcomProvider{
			version: version,
		}
	}
}
