package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	frameworkprovider "github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func TestSixKindsExposeStableResourcesAndReadOnlyDataSources(t *testing.T) {
	ctx := context.Background()
	p := New("test")()
	resources := p.Resources(ctx)
	sources := p.DataSources(ctx)
	if len(resources) != 6 || len(sources) != 6 {
		t.Fatal("six kind registrations required")
	}
	for index, kind := range []string{"tenant", "application", "resource", "group", "membership", "policy"} {
		r := resources[index]()
		var metadata resource.MetadataResponse
		r.Metadata(ctx, resource.MetadataRequest{ProviderTypeName: "asterius"}, &metadata)
		if metadata.TypeName != "asterius_"+kind {
			t.Fatal(metadata.TypeName)
		}
		var schema resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &schema)
		for _, attribute := range []string{"id", "identity_key", "external_key", "spec_json", "observed_spec_json", "revision", "owner", "deletion_protection", "retain_on_delete", "adopt", "operation_timeout"} {
			if _, ok := schema.Schema.Attributes[attribute]; !ok {
				t.Fatalf("%s missing %s", kind, attribute)
			}
		}
		var ds datasource.SchemaResponse
		sources[index]().Schema(ctx, datasource.SchemaRequest{}, &ds)
		if !ds.Schema.Attributes["id"].IsRequired() || !ds.Schema.Attributes["spec_json"].IsComputed() {
			t.Fatal("data source must read immutable identity")
		}
	}
}
func TestProviderHasExternalCredentialPathsAndNoInlineSecrets(t *testing.T) {
	p := New("test")()
	var schema frameworkprovider.SchemaResponse
	p.Schema(context.Background(), frameworkprovider.SchemaRequest{}, &schema)
	for _, forbidden := range []string{"private_key", "client_secret", "access_token", "refresh_token"} {
		if _, ok := schema.Schema.Attributes[forbidden]; ok {
			t.Fatal("inline credential attribute present")
		}
	}
	for _, required := range []string{"issuer", "issuing_tenant", "target_tenant", "target_issuer", "signing_key_file", "signing_key_id", "scopes"} {
		if _, ok := schema.Schema.Attributes[required]; !ok {
			t.Fatalf("missing config %s", required)
		}
	}
}
