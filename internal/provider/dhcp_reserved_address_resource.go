// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/francis-fisher/terraform-provider-sagemcom-fast-5598/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ resource.Resource = &DHCPReservedAddressResource{}
var _ resource.ResourceWithImportState = &DHCPReservedAddressResource{}

func NewDHCPReservedAddressResource() resource.Resource {
	return &DHCPReservedAddressResource{}
}

type DHCPReservedAddressResource struct {
	client *client.Client
}

type DHCPReservedAddressResourceModel struct {
	ID         types.String `tfsdk:"id"`
	MACAddress types.String `tfsdk:"mac_address"`
	IPAddress  types.String `tfsdk:"ip_address"`
	Hostname   types.String `tfsdk:"hostname"`
	Enabled    types.Bool   `tfsdk:"enabled"`
}

func (r *DHCPReservedAddressResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dhcp_reserved_address"
}

func (r *DHCPReservedAddressResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "DHCP Static Lease (Reserved Address) resource.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The internal ID of the DHCP reservation.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"mac_address": schema.StringAttribute{
				MarkdownDescription: "The MAC address of the client.",
				Required:            true,
			},
			"ip_address": schema.StringAttribute{
				MarkdownDescription: "The IP address assigned to the client.",
				Required:            true,
			},
			"hostname": schema.StringAttribute{
				MarkdownDescription: "Friendly hostname of the client (where known by the router).",
				Required:            true,
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Toggle state of the DHCP reservation. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
		},
	}
}

func (r *DHCPReservedAddressResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *DHCPReservedAddressResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data DHCPReservedAddressResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	enabled := true
	if !data.Enabled.IsNull() {
		enabled = data.Enabled.ValueBool()
	}

	c, err := r.client.AddDHCPReservedAddress(
		ctx,
		data.Hostname.ValueString(),
		data.MACAddress.ValueString(),
		data.IPAddress.ValueString(),
		enabled,
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating DHCP Reserved Address",
			fmt.Sprintf("Could not create reservation: %s", err.Error()),
		)
		return
	}

	data.ID = types.StringValue(fmt.Sprintf("%d", c.ID))
	data.Hostname = types.StringValue(c.Hostname)
	data.MACAddress = types.StringValue(c.MACAddress)
	data.IPAddress = types.StringValue(c.IPAddress)
	data.Enabled = types.BoolValue(c.Enabled)

	tflog.Trace(ctx, fmt.Sprintf("created DHCP reserved address resource %d", c.ID))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DHCPReservedAddressResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data DHCPReservedAddressResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	idVal := data.ID.ValueString()
	var id int
	_, err := fmt.Sscanf(idVal, "%d", &id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Parsing DHCP Reserved Address ID",
			fmt.Sprintf("Invalid ID %s: %s", idVal, err.Error()),
		)
		return
	}

	clients, err := r.client.GetDHCPReservedAddresses(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading DHCP Reserved Address",
			fmt.Sprintf("Could not retrieve clients list: %s", err.Error()),
		)
		return
	}

	found := false
	for _, c := range clients {
		if c.ID == id {
			data.Hostname = types.StringValue(c.Hostname)
			data.MACAddress = types.StringValue(c.MACAddress)
			data.IPAddress = types.StringValue(c.IPAddress)
			data.Enabled = types.BoolValue(c.Enabled)
			found = true
			break
		}
	}

	if !found {
		// Presumably the resource was deleted outside of Terraform
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DHCPReservedAddressResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan DHCPReservedAddressResourceModel
	var state DHCPReservedAddressResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	idVal := plan.ID.ValueString()
	var id int
	_, err := fmt.Sscanf(idVal, "%d", &id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Parsing DHCP Reserved Address ID",
			fmt.Sprintf("Invalid ID %s: %s", idVal, err.Error()),
		)
		return
	}

	var hostname *string
	if !plan.Hostname.Equal(state.Hostname) {
		h := plan.Hostname.ValueString()
		hostname = &h
	}

	var macaddress *string
	if !plan.MACAddress.Equal(state.MACAddress) {
		m := plan.MACAddress.ValueString()
		macaddress = &m
	}

	var ipaddress *string
	if !plan.IPAddress.Equal(state.IPAddress) {
		ip := plan.IPAddress.ValueString()
		ipaddress = &ip
	}

	var enabled *bool
	if !plan.Enabled.Equal(state.Enabled) {
		e := plan.Enabled.ValueBool()
		enabled = &e
	}

	// Update the existing DHCP reservation (sending only the changed fields to avoid conflicts on the router)
	err = r.client.UpdateDHCPReservedAddress(
		ctx,
		id,
		hostname,
		macaddress,
		ipaddress,
		enabled,
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating DHCP Reserved Address",
			fmt.Sprintf("Could not update reservation: %s", err.Error()),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *DHCPReservedAddressResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data DHCPReservedAddressResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	idVal := data.ID.ValueString()
	var id int
	_, err := fmt.Sscanf(idVal, "%d", &id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Parsing DHCP Reserved Address ID",
			fmt.Sprintf("Invalid ID %s: %s", idVal, err.Error()),
		)
		return
	}

	err = r.client.DeleteDHCPReservedAddress(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting DHCP Reserved Address",
			fmt.Sprintf("Could not delete reservation: %s", err.Error()),
		)
		return
	}
}

// When importing state, we use the MAC address to identify the entry, which we then match up with the ID (which is not exposed via the UI).
func (r *DHCPReservedAddressResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	mac := strings.TrimSpace(req.ID)
	if mac == "" {
		resp.Diagnostics.AddError("Invalid Import ID", "Import ID must be a non-empty MAC address")
		return
	}

	clients, err := r.client.GetDHCPReservedAddresses(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading DHCP Reserved Addresses during Import",
			fmt.Sprintf("Could not retrieve clients: %s", err.Error()),
		)
		return
	}

	found := false
	targetMAC := strings.ToLower(mac)
	for _, c := range clients {
		if strings.ToLower(c.MACAddress) == targetMAC {
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), fmt.Sprintf("%d", c.ID))...)
			found = true
			break
		}
	}

	if !found {
		resp.Diagnostics.AddError(
			"Resource Not Found",
			fmt.Sprintf("Could not find DHCP reserved address with MAC address %s", mac),
		)
		return
	}
}
