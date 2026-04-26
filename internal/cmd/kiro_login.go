package cmd

import (
	"context"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/util"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
	log "github.com/sirupsen/logrus"
)

// DoKiroImport imports a Kiro token from the Kiro IDE token file at
// ~/.aws/sso/cache/kiro-auth-token.json and persists it as a "kiro" provider credential.
func DoKiroImport(cfg *config.Config, options *LoginOptions) {
	if cfg == nil {
		cfg = &config.Config{}
	}
	if resolved, errResolve := util.ResolveAuthDir(cfg.AuthDir); errResolve == nil {
		cfg.AuthDir = resolved
	}

	authenticator := sdkAuth.NewKiroAuthenticator()
	record, errImport := authenticator.ImportFromKiroIDE(context.Background(), cfg)
	if errImport != nil {
		log.Errorf("Kiro token import failed: %v", errImport)
		fmt.Println("\nMake sure you have logged in to Kiro IDE first:")
		fmt.Println("  1. Open Kiro IDE")
		fmt.Println("  2. Sign in with Google, GitHub, or AWS Builder ID")
		fmt.Println("  3. Complete the login process")
		fmt.Println("  4. Run this command again")
		return
	}

	store := sdkAuth.GetTokenStore()
	if setter, ok := store.(interface{ SetBaseDir(string) }); ok {
		setter.SetBaseDir(cfg.AuthDir)
	}

	path, errSave := store.Save(context.Background(), record)
	if errSave != nil {
		log.Errorf("kiro-import: save credential failed: %v", errSave)
		return
	}

	fmt.Printf("Kiro credentials imported: %s\n", path)
	if record != nil && record.Label != "" {
		fmt.Printf("Imported as %s\n", record.Label)
	}
}
