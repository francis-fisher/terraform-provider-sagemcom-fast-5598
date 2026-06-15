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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ resource.Resource = &PortForwardResource{}
var _ resource.ResourceWithImportState = &PortForwardResource{}

func NewPortForwardResource() resource.Resource {
	return &PortForwardResource{}
}

type PortForwardResource struct {
	client *client.Client
}

type PortForwardResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Enabled         types.Bool   `tfsdk:"enabled"`
	Description     types.String `tfsdk:"description"`
	Protocol        types.String `tfsdk:"protocol"`
	LocalIPAddress  types.String `tfsdk:"local_ip_address"`
	RemoteIPAddress types.String `tfsdk:"remote_ip_address"`
	RemotePort      types.Int64  `tfsdk:"remote_port"`
	LocalPort       types.Int64  `tfsdk:"local_port"`
	RemoteEndPort   types.Int64  `tfsdk:"remote_end_port"`
}

func (r *PortForwardResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_port_forward"
}

func (r *PortForwardResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "IPv4 Port Forwarding rule resource.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The internal ID of the port forwarding rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Toggle state of the port forwarding rule. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Description or name of the port forwarding rule.",
				Required:            true,
			},
			"protocol": schema.StringAttribute{
				MarkdownDescription: "Protocol to forward. Allowed values are `all` (TCP - UDP), `tcp`, `udp`, `both`, `icmp`, `gre`, `ah`, `esp`, and `other`.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"local_ip_address": schema.StringAttribute{
				MarkdownDescription: "Local IP address of the target machine on the LAN.",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"remote_ip_address": schema.StringAttribute{
				MarkdownDescription: "Remote IP address allowed to access. Defaults to `*` (any).",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("*"),
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"remote_port": schema.Int64Attribute{
				MarkdownDescription: "The port that the router listens on for incoming connections from the intenet.",
				Required:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"local_port": schema.Int64Attribute{
				MarkdownDescription: "Local port to forward to on the target machine.",
				Required:            true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"remote_end_port": schema.Int64Attribute{
				MarkdownDescription: "Remote end port for port ranges. Defaults to `0` (indicating only a single port is to be forwarded).",
				Optional:            true,
				Computed:            true,
				Default:             int64default.StaticInt64(0),
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *PortForwardResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *PortForwardResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data PortForwardResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	enabled := true
	if !data.Enabled.IsNull() {
		enabled = data.Enabled.ValueBool()
	}

	remoteEndPort := int64(0)
	if !data.RemoteEndPort.IsNull() {
		remoteEndPort = data.RemoteEndPort.ValueInt64()
	}

	remoteIP := "*"
	if !data.RemoteIPAddress.IsNull() {
		remoteIP = data.RemoteIPAddress.ValueString()
	}

	// Create new Port Forwarding rule
	pf, err := r.client.AddPortForward(
		ctx,
		data.Description.ValueString(),
		data.LocalIPAddress.ValueString(),
		remoteIP,
		int(data.RemotePort.ValueInt64()),
		int(data.LocalPort.ValueInt64()),
		int(remoteEndPort),
		data.Protocol.ValueString(),
		enabled,
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Creating Port Forward",
			fmt.Sprintf("Could not create port forwarding rule: %s", err.Error()),
		)
		return
	}

	// Save data into the model to return to Terraform state
	data.ID = types.StringValue(fmt.Sprintf("%d", pf.ID))
	data.Description = types.StringValue(pf.Description)
	data.LocalIPAddress = types.StringValue(pf.InternalIP)
	if pf.ExternalIP == "" {
		data.RemoteIPAddress = types.StringValue("*")
	} else {
		data.RemoteIPAddress = types.StringValue(pf.ExternalIP)
	}
	data.RemotePort = types.Int64Value(int64(pf.ExternalPort))
	data.LocalPort = types.Int64Value(int64(pf.InternalPort))
	data.RemoteEndPort = types.Int64Value(int64(pf.ExternalEndPort))
	data.Protocol = types.StringValue(pf.Protocol)
	data.Enabled = types.BoolValue(pf.Enabled)

	tflog.Trace(ctx, fmt.Sprintf("created port forward resource %d", pf.ID))

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PortForwardResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data PortForwardResourceModel

	// Read prior state data
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	idVal := data.ID.ValueString()
	var id int
	_, err := fmt.Sscanf(idVal, "%d", &id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Parsing Port Forward ID",
			fmt.Sprintf("Invalid ID %s: %s", idVal, err.Error()),
		)
		return
	}

	// Retrieve all port forwards to check if this one still exists
	rules, err := r.client.GetPortForwards(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Port Forward",
			fmt.Sprintf("Could not retrieve rules list: %s", err.Error()),
		)
		return
	}

	found := false
	for _, rule := range rules {
		if rule.ID == id {
			data.Description = types.StringValue(rule.Description)
			data.LocalIPAddress = types.StringValue(rule.InternalIP)
			if rule.ExternalIP == "" {
				data.RemoteIPAddress = types.StringValue("*")
			} else {
				data.RemoteIPAddress = types.StringValue(rule.ExternalIP)
			}
			data.RemotePort = types.Int64Value(int64(rule.ExternalPort))
			data.LocalPort = types.Int64Value(int64(rule.InternalPort))
			data.RemoteEndPort = types.Int64Value(int64(rule.ExternalEndPort))
			data.Protocol = types.StringValue(rule.Protocol)
			data.Enabled = types.BoolValue(rule.Enabled)
			found = true
			break
		}
	}

	if !found {
		resp.State.RemoveResource(ctx)
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *PortForwardResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan PortForwardResourceModel
	var state PortForwardResourceModel

	// Read plan and state
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
			"Error Parsing Port Forward ID",
			fmt.Sprintf("Invalid ID %s: %s", idVal, err.Error()),
		)
		return
	}

	remoteIP := "*"
	if !plan.RemoteIPAddress.IsNull() {
		remoteIP = plan.RemoteIPAddress.ValueString()
	}

	err = r.client.UpdatePortForward(
		ctx,
		id,
		plan.Description.ValueString(),
		plan.LocalIPAddress.ValueString(),
		remoteIP,
		int(plan.RemotePort.ValueInt64()),
		int(plan.LocalPort.ValueInt64()),
		int(plan.RemoteEndPort.ValueInt64()),
		plan.Protocol.ValueString(),
		plan.Enabled.ValueBool(),
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Updating Port Forward",
			fmt.Sprintf("Could not update port forwarding rule: %s", err.Error()),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *PortForwardResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data PortForwardResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	idVal := data.ID.ValueString()
	var id int
	_, err := fmt.Sscanf(idVal, "%d", &id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Parsing Port Forward ID",
			fmt.Sprintf("Invalid ID %s: %s", idVal, err.Error()),
		)
		return
	}

	err = r.client.DeletePortForward(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Port Forward",
			fmt.Sprintf("Could not delete port forwarding rule: %s", err.Error()),
		)
		return
	}
}

// When importing state, we use the description to identify the entry, which we then match up with the ID (which is not exposed via the UI).
func (r *PortForwardResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	description := strings.TrimSpace(req.ID)
	if description == "" {
		resp.Diagnostics.AddError("Invalid Import ID", "Import ID must be a non-empty description")
		return
	}

	rules, err := r.client.GetPortForwards(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Reading Port Forwards during Import",
			fmt.Sprintf("Could not retrieve rules: %s", err.Error()),
		)
		return
	}

	var matches []client.PortForward
	for _, rule := range rules {
		if rule.Description == description {
			matches = append(matches, rule)
		}
	}

	if len(matches) == 0 {
		resp.Diagnostics.AddError(
			"Resource Not Found",
			fmt.Sprintf("Could not find port forwarding rule with description %q", description),
		)
		return
	}

	if len(matches) > 1 {
		resp.Diagnostics.AddError(
			"Ambiguous Resource Reference",
			fmt.Sprintf("cannot import as multiple entries have same description %q", description),
		)
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), fmt.Sprintf("%d", matches[0].ID))...)
}
