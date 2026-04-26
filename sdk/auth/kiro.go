package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	kiroauth "github.com/router-for-me/CLIProxyAPI/v6/internal/auth/kiro"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

// extractKiroIdentifier extracts a meaningful identifier for file naming.
// Returns account name if provided, otherwise profile ARN ID, then client ID.
// All extracted values are sanitized to prevent path injection attacks.
func extractKiroIdentifier(accountName, profileArn, clientID string) string {
	// Priority 1: Use account name if provided
	if accountName != "" {
		return kiroauth.SanitizeEmailForFilename(accountName)
	}

	// Priority 2: Use profile ARN ID part (sanitized to prevent path injection)
	if profileArn != "" {
		parts := strings.Split(profileArn, "/")
		if len(parts) >= 2 {
			// Sanitize the ARN component to prevent path traversal
			return kiroauth.SanitizeEmailForFilename(parts[len(parts)-1])
		}
	}

	// Priority 3: Use client ID (for IDC auth without email/profileArn)
	if clientID != "" {
		return kiroauth.SanitizeEmailForFilename(clientID)
	}

	// Fallback: timestamp
	return fmt.Sprintf("%d", time.Now().UnixNano()%100000)
}

// KiroAuthenticator implements the Authenticator interface for Kiro (AWS CodeWhisperer).
type KiroAuthenticator struct{}

// NewKiroAuthenticator constructs a Kiro authenticator.
func NewKiroAuthenticator() *KiroAuthenticator {
	return &KiroAuthenticator{}
}

// Provider returns the provider key for the authenticator.
func (a *KiroAuthenticator) Provider() string {
	return "kiro"
}

// RefreshLead indicates how soon before expiry a refresh should be attempted.
// Set to 20 minutes for proactive refresh before token expiry.
func (a *KiroAuthenticator) RefreshLead() *time.Duration {
	d := 20 * time.Minute
	return &d
}

// createAuthRecord creates a coreauth.Auth record from Kiro token data.
func (a *KiroAuthenticator) createAuthRecord(tokenData *kiroauth.KiroTokenData, source string) (*coreauth.Auth, error) {
	// Parse expires_at
	expiresAt, err := time.Parse(time.RFC3339, tokenData.ExpiresAt)
	if err != nil {
		expiresAt = time.Now().Add(1 * time.Hour)
	}

	// Determine label and identifier based on auth method
	var label, idPart string
	if tokenData.AuthMethod == "idc" {
		label = "kiro-idc"
		// For IDC auth, always use clientID as identifier
		if tokenData.ClientID != "" {
			idPart = kiroauth.SanitizeEmailForFilename(tokenData.ClientID)
		} else {
			idPart = fmt.Sprintf("%d", time.Now().UnixNano()%100000)
		}
	} else {
		label = fmt.Sprintf("kiro-%s", source)
		idPart = extractKiroIdentifier(tokenData.Email, tokenData.ProfileArn, tokenData.ClientID)
	}

	now := time.Now()
	fileName := fmt.Sprintf("%s-%s.json", label, idPart)

	metadata := map[string]any{
		"type":          "kiro",
		"access_token":  tokenData.AccessToken,
		"refresh_token": tokenData.RefreshToken,
		"profile_arn":   tokenData.ProfileArn,
		"expires_at":    tokenData.ExpiresAt,
		"auth_method":   tokenData.AuthMethod,
		"provider":      tokenData.Provider,
		"client_id":     tokenData.ClientID,
		"client_secret": tokenData.ClientSecret,
		"email":         tokenData.Email,
	}

	// Add IDC-specific fields if present
	if tokenData.StartURL != "" {
		metadata["start_url"] = tokenData.StartURL
	}
	if tokenData.Region != "" {
		metadata["region"] = tokenData.Region
	}

	attributes := map[string]string{
		"profile_arn": tokenData.ProfileArn,
		"source":      source,
		"email":       tokenData.Email,
	}

	// Add IDC-specific attributes if present
	if tokenData.AuthMethod == "idc" {
		attributes["source"] = "aws-idc"
		if tokenData.StartURL != "" {
			attributes["start_url"] = tokenData.StartURL
		}
		if tokenData.Region != "" {
			attributes["region"] = tokenData.Region
		}
	}

	record := &coreauth.Auth{
		ID:               fileName,
		Provider:         "kiro",
		FileName:         fileName,
		Label:            label,
		Status:           coreauth.StatusActive,
		CreatedAt:        now,
		UpdatedAt:        now,
		Metadata:         metadata,
		Attributes:       attributes,
		NextRefreshAfter: expiresAt.Add(-20 * time.Minute),
	}

	if tokenData.Email != "" {
		fmt.Printf("\n✓ Kiro authentication completed successfully! (Account: %s)\n", tokenData.Email)
	} else {
		fmt.Println("\n✓ Kiro authentication completed successfully!")
	}

	return record, nil
}

// Login performs OAuth login for Kiro. Full AWS SSO/Builder-ID login is not yet supported;
// use --kiro-import to import credentials from Kiro IDE instead.
func (a *KiroAuthenticator) Login(_ context.Context, _ *config.Config, _ *LoginOptions) (*coreauth.Auth, error) {
	return nil, fmt.Errorf("kiro: interactive login is not yet supported — use --kiro-import to import your token from Kiro IDE (~/.aws/sso/cache/kiro-auth-token.json)")
}

// LoginWithGoogle returns an error because Google login is not available for third-party applications
// due to AWS Cognito restrictions. Use --kiro-import after logging in via Kiro IDE instead.
func (a *KiroAuthenticator) LoginWithGoogle(_ context.Context, _ *config.Config, _ *LoginOptions) (*coreauth.Auth, error) {
	return nil, fmt.Errorf("Google login is not available for third-party applications due to AWS Cognito restrictions.\n\nAlternatives:\n  1. Import token from Kiro IDE: --kiro-import\n\nTo get a token from Kiro IDE:\n  1. Open Kiro IDE and login with Google\n  2. Run: --kiro-import")
}

// LoginWithGitHub returns an error because GitHub login is not available for third-party applications
// due to AWS Cognito restrictions. Use --kiro-import after logging in via Kiro IDE instead.
func (a *KiroAuthenticator) LoginWithGitHub(_ context.Context, _ *config.Config, _ *LoginOptions) (*coreauth.Auth, error) {
	return nil, fmt.Errorf("GitHub login is not available for third-party applications due to AWS Cognito restrictions.\n\nAlternatives:\n  1. Import token from Kiro IDE: --kiro-import\n\nTo get a token from Kiro IDE:\n  1. Open Kiro IDE and login with GitHub\n  2. Run: --kiro-import")
}

// ImportFromKiroIDE imports a token from Kiro IDE's token file at
// ~/.aws/sso/cache/kiro-auth-token.json and returns a populated auth record.
func (a *KiroAuthenticator) ImportFromKiroIDE(_ context.Context, _ *config.Config) (*coreauth.Auth, error) {
	tokenData, err := kiroauth.LoadKiroIDEToken()
	if err != nil {
		return nil, fmt.Errorf("failed to load Kiro IDE token: %w", err)
	}

	// Parse expires_at
	expiresAt, err := time.Parse(time.RFC3339, tokenData.ExpiresAt)
	if err != nil {
		expiresAt = time.Now().Add(1 * time.Hour)
	}

	// Extract email from JWT if not already set (for imported tokens)
	if tokenData.Email == "" {
		tokenData.Email = kiroauth.ExtractEmailFromJWT(tokenData.AccessToken)
	}

	// Extract identifier for file naming
	idPart := extractKiroIdentifier(tokenData.Email, tokenData.ProfileArn, tokenData.ClientID)
	// Sanitize provider to prevent path traversal (defense-in-depth)
	provider := kiroauth.SanitizeEmailForFilename(strings.ToLower(strings.TrimSpace(tokenData.Provider)))
	if provider == "" {
		provider = "imported" // Fallback for legacy tokens without provider
	}

	now := time.Now()
	fileName := fmt.Sprintf("kiro-%s-%s.json", provider, idPart)

	record := &coreauth.Auth{
		ID:       fileName,
		Provider: "kiro",
		FileName: fileName,
		Label:    fmt.Sprintf("kiro-%s", provider),
		Status:   coreauth.StatusActive,
		CreatedAt: now,
		UpdatedAt: now,
		Metadata: map[string]any{
			"type":          "kiro",
			"access_token":  tokenData.AccessToken,
			"refresh_token": tokenData.RefreshToken,
			"profile_arn":   tokenData.ProfileArn,
			"expires_at":    tokenData.ExpiresAt,
			"auth_method":   tokenData.AuthMethod,
			"provider":      tokenData.Provider,
			"client_id":     tokenData.ClientID,
			"client_secret": tokenData.ClientSecret,
			"email":         tokenData.Email,
			"region":        tokenData.Region,
			"start_url":     tokenData.StartURL,
		},
		Attributes: map[string]string{
			"profile_arn": tokenData.ProfileArn,
			"source":      "kiro-ide-import",
			"email":       tokenData.Email,
			"region":      tokenData.Region,
		},
		NextRefreshAfter: expiresAt.Add(-20 * time.Minute),
	}

	// Display the email if extracted
	if tokenData.Email != "" {
		fmt.Printf("\n✓ Imported Kiro token from IDE (Provider: %s, Account: %s)\n", tokenData.Provider, tokenData.Email)
	} else {
		fmt.Printf("\n✓ Imported Kiro token from IDE (Provider: %s)\n", tokenData.Provider)
	}

	return record, nil
}

// Refresh refreshes an expired Kiro token. Full refresh via SSO OIDC is not yet supported;
// run --kiro-import again after refreshing your Kiro IDE session to update credentials.
func (a *KiroAuthenticator) Refresh(_ context.Context, _ *config.Config, _ *coreauth.Auth) (*coreauth.Auth, error) {
	return nil, ErrRefreshNotSupported
}
