package bifrostprovider

import (
	"context"
	"fmt"

	"github.com/maximhq/bifrost/core/schemas"
)

// Account implements schemas.Account for a single provider, delegating key
// construction to the caller. Both GetConfiguredProviders and GetConfigForProvider
// are handled generically; callers only supply the []schemas.Key slice.
type Account struct {
	provider schemas.ModelProvider
	keys     []schemas.Key
}

var _ schemas.Account = (*Account)(nil)

// NewAccount returns an Account for the given provider and keys.
func NewAccount(provider schemas.ModelProvider, keys []schemas.Key) *Account {
	return &Account{provider: provider, keys: keys}
}

func (a *Account) GetConfiguredProviders() ([]schemas.ModelProvider, error) {
	return []schemas.ModelProvider{a.provider}, nil
}

func (a *Account) GetKeysForProvider(_ context.Context, provider schemas.ModelProvider) ([]schemas.Key, error) {
	if provider != a.provider {
		return nil, fmt.Errorf("provider %s not supported", provider)
	}
	return a.keys, nil
}

func (a *Account) GetConfigForProvider(provider schemas.ModelProvider) (*schemas.ProviderConfig, error) {
	if provider != a.provider {
		return nil, fmt.Errorf("provider %s not supported", provider)
	}
	return &schemas.ProviderConfig{
		NetworkConfig:            schemas.DefaultNetworkConfig,
		ConcurrencyAndBufferSize: schemas.DefaultConcurrencyAndBufferSize,
	}, nil
}
