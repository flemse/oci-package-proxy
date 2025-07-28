package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@v0.19.2 generate --provider-name example

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: func() *schema.Provider {
			return &schema.Provider{
				Schema: map[string]*schema.Schema{},
				ResourcesMap: map[string]*schema.Resource{
					"example_test": {
						CreateContext: func(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
							return nil
						},
					},
				},
			}
		},
	})
}
