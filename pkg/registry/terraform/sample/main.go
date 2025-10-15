package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: func() *schema.Provider {
			return &schema.Provider{
				Schema: map[string]*schema.Schema{},
				ResourcesMap: map[string]*schema.Resource{
					"example_resource": {
						Schema: map[string]*schema.Schema{
							"name": {
								Type:     schema.TypeString,
								Required: true,
							},
						},
						CreateContext: resourceCreate,
						ReadContext:   resourceRead,
						UpdateContext: resourceUpdate,
						DeleteContext: resourceDelete,
					},
				},
			}
		},
	})
}

func resourceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId("example")
	return nil
}

func resourceRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}

func resourceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}

func resourceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId("")
	return nil
}
