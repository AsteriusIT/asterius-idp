package main

import (
	"context"
	"flag"
	"log"

	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

func main() {
	debug := flag.Bool("debug", false, "serve with managed debug reattachment")
	flag.Parse()
	if err := providerserver.Serve(context.Background(), provider.New("0.1.0"), providerserver.ServeOpts{Address: "registry.terraform.io/asterius/asterius", Debug: *debug}); err != nil {
		log.Fatal("provider server failed")
	}
}
