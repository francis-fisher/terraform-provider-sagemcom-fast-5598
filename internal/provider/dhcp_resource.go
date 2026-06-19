// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/francis-fisher/terraform-provider-sagemcom-fast-5598/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ resource.Resource = &DHCPResource{}
var _ resource.ResourceWithImportState = &DHCPResource{}

func NewDHCPResource() resource.Resource {
	return &DHCPResource{}
}

type DHCPResource struct {
	client *client.Client
}

type DHCPResourceModel struct {
	ID             types.String `tfsdk:"id"`
	EnableDHCP     types.Bool   `tfsdk:"enable_dhcp"`
	MinAddress     types.String `tfsdk:"min_address"`
	MaxAddress     types.String `tfsdk:"max_address"`
	LeaseTime      types.Int64  `tfsdk:"lease_time"`
	DNSIPv4Mode    types.String `tfsdk:"dns_ipv4_mode"`
	DNSIPv4Servers types.List   `tfsdk:"dns_ipv4_servers"`
	DNSIPv6Mode    types.String `tfsdk:"dns_ipv6_mode"`
	DNSIPv6Servers types.List   `tfsdk:"dns_ipv6_servers"`
}

func (r *DHCPResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dhcp"
}

func (r *DHCPResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "DHCP Server and DNS Advertisement configuration resource.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The ID of the DHCP settings (always 'dhcp').",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"enable_dhcp": schema.BoolAttribute{
				MarkdownDescription: "Enable or disable the DHCP server. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"min_address": schema.StringAttribute{
				MarkdownDescription: "The lowest IP address in the DHCP pool.",
				Required:            true,
			},
			"max_address": schema.StringAttribute{
				MarkdownDescription: "The highest IP address in the DHCP pool.",
				Required:            true,
			},
			"lease_time": schema.Int64Attribute{
				MarkdownDescription: "The lease time of the DHCP server in seconds. Defaults to `43200`.",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(43200),
			},
			"dns_ipv4_mode": schema.StringAttribute{
				MarkdownDescription: "DNS IPv4 advertisement mode. Must be 'DHCP' (advertise ISP DNS) or 'STATIC' (advertise user DNS). Defaults to `DHCP`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("DHCP"),
			},
			"dns_ipv4_servers": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of 1 or 2 IPv4 DNS servers to advertise when dns_ipv4_mode is 'STATIC'.",
				Optional:            true,
			},
			"dns_ipv6_mode": schema.StringAttribute{
				MarkdownDescription: "DNS IPv6 advertisement mode. Must be 'DHCP' (advertise ISP DNS) or 'STATIC' (advertise user DNS). Defaults to `DHCP`.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("DHCP"),
			},
			"dns_ipv6_servers": schema.ListAttribute{
				ElementType:         types.StringType,
				MarkdownDescription: "List of 1 or 2 IPv6 DNS servers to advertise when dns_ipv6_mode is 'STATIC'.",
				Optional:            true,
			},
		},
	}
}

func (r *DHCPResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = c
}

func validateDHCPModel(ctx context.Context, data *DHCPResourceModel) diag.Diagnostics {
	var diags diag.Diagnostics

	v4Mode := data.DNSIPv4Mode.ValueString()
	if v4Mode != "DHCP" && v4Mode != "STATIC" {
		diags.AddError(
			"Invalid Attribute Value",
			"dns_ipv4_mode must be either 'DHCP' or 'STATIC'",
		)
	}

	v6Mode := data.DNSIPv6Mode.ValueString()
	if v6Mode != "DHCP" && v6Mode != "STATIC" {
		diags.AddError(
			"Invalid Attribute Value",
			"dns_ipv6_mode must be either 'DHCP' or 'STATIC'",
		)
	}

	if v4Mode == "STATIC" {
		if data.DNSIPv4Servers.IsNull() || data.DNSIPv4Servers.IsUnknown() {
			diags.AddError(
				"Missing Required Attribute",
				"dns_ipv4_servers must be configured when dns_ipv4_mode is 'STATIC'",
			)
		} else {
			var servers []string
			d := data.DNSIPv4Servers.ElementsAs(ctx, &servers, false)
			diags.Append(d...)
			if !diags.HasError() && (len(servers) < 1 || len(servers) > 2) {
				diags.AddError(
					"Invalid Attribute Value",
					fmt.Sprintf("dns_ipv4_servers must contain 1 or 2 DNS servers, got: %d", len(servers)),
				)
			}
		}
	}

	if v6Mode == "STATIC" {
		if data.DNSIPv6Servers.IsNull() || data.DNSIPv6Servers.IsUnknown() {
			diags.AddError(
				"Missing Required Attribute",
				"dns_ipv6_servers must be configured when dns_ipv6_mode is 'STATIC'",
			)
		} else {
			var servers []string
			d := data.DNSIPv6Servers.ElementsAs(ctx, &servers, false)
			diags.Append(d...)
			if !diags.HasError() && (len(servers) < 1 || len(servers) > 2) {
				diags.AddError(
					"Invalid Attribute Value",
					fmt.Sprintf("dns_ipv6_servers must contain 1 or 2 DNS servers, got: %d", len(servers)),
				)
			}
		}
	}

	return diags
}

func (r *DHCPResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data DHCPResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(validateDHCPModel(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.UpdateDHCPServer(
		ctx,
		data.EnableDHCP.ValueBool(),
		data.MinAddress.ValueString(),
		data.MaxAddress.ValueString(),
		int(data.LeaseTime.ValueInt64()),
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating DHCP Config",
			fmt.Sprintf("Could not configure DHCP server: %s", err.Error()),
		)
		return
	}

	enableV4Static := data.DNSIPv4Mode.ValueString() == "STATIC"
	var v4Servers []string
	if enableV4Static {
		d := data.DNSIPv4Servers.ElementsAs(ctx, &v4Servers, false)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	err = r.client.UpdateDNSIPv4(ctx, enableV4Static, strings.Join(v4Servers, ","))
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating DHCP Config",
			fmt.Sprintf("Could not configure DNS IPv4: %s", err.Error()),
		)
		return
	}

	enableV6Static := data.DNSIPv6Mode.ValueString() == "STATIC"
	var v6Servers []string
	if enableV6Static {
		d := data.DNSIPv6Servers.ElementsAs(ctx, &v6Servers, false)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	err = r.client.UpdateDNSIPv6(ctx, enableV6Static, strings.Join(v6Servers, ","))
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating DHCP Config",
			fmt.Sprintf("Could not configure DNS IPv6: %s", err.Error()),
		)
		return
	}

	data.ID = types.StringValue("dhcp")

	tflog.Trace(ctx, "configured DHCP server and DNS settings")

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DHCPResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data DHCPResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	dhcp, err := r.client.GetDHCPServer(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading DHCP Settings",
			fmt.Sprintf("Could not read DHCP settings: %s", err.Error()),
		)
		return
	}

	data.EnableDHCP = types.BoolValue(dhcp.Enable)
	data.MinAddress = types.StringValue(dhcp.MinAddress)
	data.MaxAddress = types.StringValue(dhcp.MaxAddress)
	data.LeaseTime = types.Int64Value(int64(dhcp.LeaseTime))

	dns4, err := r.client.GetDNSIPv4(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading DNS IPv4 Settings",
			fmt.Sprintf("Could not read DNS IPv4 settings: %s", err.Error()),
		)
		return
	}

	if dns4.DNSMode == "STATIC" {
		data.DNSIPv4Mode = types.StringValue("STATIC")
		var servers []string
		if dns4.Static.Servers != "" {
			servers = strings.Split(dns4.Static.Servers, ",")
		}
		serversList, diags := types.ListValueFrom(ctx, types.StringType, servers)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.DNSIPv4Servers = serversList
	} else {
		data.DNSIPv4Mode = types.StringValue("DHCP")
		if data.DNSIPv4Servers.IsNull() {
			data.DNSIPv4Servers = types.ListNull(types.StringType)
		} else {
			serversList, diags := types.ListValueFrom(ctx, types.StringType, []string{})
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}
			data.DNSIPv4Servers = serversList
		}
	}

	dns6, err := r.client.GetDNSIPv6(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading DNS IPv6 Settings",
			fmt.Sprintf("Could not read DNS IPv6 settings: %s", err.Error()),
		)
		return
	}

	if dns6.DNSMode == "STATIC" {
		data.DNSIPv6Mode = types.StringValue("STATIC")
		var servers []string
		if dns6.Static.Servers != "" {
			servers = strings.Split(dns6.Static.Servers, ",")
		}
		serversList, diags := types.ListValueFrom(ctx, types.StringType, servers)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		data.DNSIPv6Servers = serversList
	} else {
		data.DNSIPv6Mode = types.StringValue("DHCP")
		if data.DNSIPv6Servers.IsNull() {
			data.DNSIPv6Servers = types.ListNull(types.StringType)
		} else {
			serversList, diags := types.ListValueFrom(ctx, types.StringType, []string{})
			resp.Diagnostics.Append(diags...)
			if resp.Diagnostics.HasError() {
				return
			}
			data.DNSIPv6Servers = serversList
		}
	}

	data.ID = types.StringValue("dhcp")

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DHCPResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan DHCPResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(validateDHCPModel(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.UpdateDHCPServer(
		ctx,
		plan.EnableDHCP.ValueBool(),
		plan.MinAddress.ValueString(),
		plan.MaxAddress.ValueString(),
		int(plan.LeaseTime.ValueInt64()),
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating DHCP Config",
			fmt.Sprintf("Could not configure DHCP server: %s", err.Error()),
		)
		return
	}

	enableV4Static := plan.DNSIPv4Mode.ValueString() == "STATIC"
	var v4Servers []string
	if enableV4Static {
		d := plan.DNSIPv4Servers.ElementsAs(ctx, &v4Servers, false)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	err = r.client.UpdateDNSIPv4(ctx, enableV4Static, strings.Join(v4Servers, ","))
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating DHCP Config",
			fmt.Sprintf("Could not configure DNS IPv4: %s", err.Error()),
		)
		return
	}

	enableV6Static := plan.DNSIPv6Mode.ValueString() == "STATIC"
	var v6Servers []string
	if enableV6Static {
		d := plan.DNSIPv6Servers.ElementsAs(ctx, &v6Servers, false)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	err = r.client.UpdateDNSIPv6(ctx, enableV6Static, strings.Join(v6Servers, ","))
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating DHCP Config",
			fmt.Sprintf("Could not configure DNS IPv6: %s", err.Error()),
		)
		return
	}

	plan.ID = types.StringValue("dhcp")

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DHCPResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// DHCP server is a singleton and cannot be deleted physically from the router.
	// We simply trace the event and clean up state.
	tflog.Trace(ctx, "removing DHCP server configuration from Terraform state (no changes made to router)")
}

func (r *DHCPResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
