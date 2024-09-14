package tokencache

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/sk1m/oidc-cli/internal/oidc"
)

func TestRepository_FindByKey(t *testing.T) {
	var r Repository

	t.Run("Success", func(t *testing.T) {
		dir := t.TempDir()
		key := &Key{
			IssuerURL:   "YOUR_ISSUER",
			ClientID:    "YOUR_CLIENT_ID",
			ExtraScopes: []string{"openid", "email"},
		}
		json := `{"id_token":"YOUR_ID_TOKEN","refresh_token":"YOUR_REFRESH_TOKEN"}`
		filename, err := computeFilename(key)
		if err != nil {
			t.Errorf("could not compute the key: %s", err)
		}
		p := filepath.Join(dir, filename)
		if err := os.WriteFile(p, []byte(json), 0600); err != nil {
			t.Fatalf("could not write to the temp file: %s", err)
		}

		got, err := r.FindByKey(dir, key)
		if err != nil {
			t.Errorf("err wants nil but %+v", err)
		}
		want := &oidc.Token{IDToken: "YOUR_ID_TOKEN", RefreshToken: "YOUR_REFRESH_TOKEN"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestRepository_Save(t *testing.T) {
	var r Repository

	t.Run("Success", func(t *testing.T) {
		dir := t.TempDir()
		key := &Key{
			IssuerURL:   "YOUR_ISSUER",
			ClientID:    "YOUR_CLIENT_ID",
			ExtraScopes: []string{"openid", "email"},
		}
		tokenSet := oidc.Token{IDToken: "YOUR_ID_TOKEN", RefreshToken: "YOUR_REFRESH_TOKEN"}
		if err := r.Save(dir, key, tokenSet); err != nil {
			t.Errorf("err wants nil but %+v", err)
		}

		filename, err := computeFilename(key)
		if err != nil {
			t.Errorf("could not compute the key: %s", err)
		}
		p := filepath.Join(dir, filename)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("could not read the token cache file: %s", err)
		}
		want := `{"id_token":"YOUR_ID_TOKEN","refresh_token":"YOUR_REFRESH_TOKEN"}
`
		got := string(b)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("mismatch (-want +got):\n%s", diff)
		}
	})
}
