package acceptance

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AsteriusIT/asterius-idp/providers/terraform/internal/client"
)

func TestLiveDeletionReceiptAfterParentRemoval(t *testing.T) {
	if os.Getenv("ASTERIUS_ACCEPTANCE_LIVE") != "1" {
		t.Skip("isolated real Asterius fixture required")
	}
	c, err := client.New(client.Config{Issuer: os.Getenv("ASTERIUS_ISSUER"), ClientID: os.Getenv("ASTERIUS_CLIENT_ID"), KeyFile: os.Getenv("ASTERIUS_SIGNING_KEY_FILE"), KeyID: os.Getenv("ASTERIUS_SIGNING_KEY_ID"), CAFile: os.Getenv("ASTERIUS_CA_FILE"), Resource: os.Getenv("ASTERIUS_TOKEN_RESOURCE"), Scopes: strings.Fields("admin.session:read admin.groups:read admin.groups:write admin.memberships:read admin.memberships:write"), Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	key, err := client.RandomID()
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(map[string]any{"name": fmt.Sprintf("receipt-%x", time.Now().UnixNano()), "display_name": "Receipt fixture"})
	group, err := c.Create(ctx, "group", "receipt/group/"+key, spec, false)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := client.ParseID(group.ID)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ = json.Marshal(map[string]any{"group_id": parts[2], "user_id": os.Getenv("ASTERIUS_ACCEPTANCE_USER_ID")})
	member, err := c.Create(ctx, "membership", "receipt/member/"+key, spec, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Mutate(ctx, "DELETE", member.ID, "", member.Revision, nil); err != nil {
		t.Fatal(err)
	}
	group, err = c.Read(ctx, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Mutate(ctx, "DELETE", group.ID, "", group.Revision, nil); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Mutate(ctx, "DELETE", member.ID, "", member.Revision, nil); err != nil {
		t.Fatalf("exact membership deletion receipt failed after parent deletion: %v", err)
	}
	if _, err = c.Create(ctx, "membership", "receipt/missing-parent/"+key, spec, false); !client.IsNotFound(err) {
		t.Fatalf("new membership without live parent must fail404, got %v", err)
	}
	t.Log("exact receipt retry succeeds after parent removal; new missing-parent edge fails404")
}
