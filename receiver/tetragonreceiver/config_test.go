// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tetragonreceiver

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/confmaptest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/tetragonreceiver/internal/metadata"
)

func TestLoadConfig(t *testing.T) {
	cm, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
	require.NoError(t, err)

	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()

	sub, err := cm.Sub(metadata.Type.String())
	require.NoError(t, err)
	require.NoError(t, sub.Unmarshal(cfg))

	assert.NoError(t, confmap.Validate(cfg))
	assert.Equal(t, factory.CreateDefaultConfig(), cfg)
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{
			name: "valid default config",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				return c
			}(),
		},
		{
			name: "missing endpoint",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				c.ClientConfig = configgrpc.ClientConfig{Endpoint: ""}
				return c
			}(),
			wantErr: "endpoint must be specified",
		},
		{
			name: "invalid buffer_size",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				c.BufferSize = 0
				return c
			}(),
			wantErr: "buffer_size must be at least 1",
		},
		{
			name: "invalid workers",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				c.Workers = 0
				return c
			}(),
			wantErr: "workers must be at least 1",
		},
		{
			name: "invalid field filter action",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				c.FieldFilters = []FieldFilterConfig{{Action: "INVALID"}}
				return c
			}(),
			wantErr: "field_filters[0].action must be INCLUDE or EXCLUDE",
		},
		{
			name: "redaction_filters rejected",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				c.RedactionFilters = []RedactionFilterConfig{{Redact: []string{"--password(?:\\s+|=)(\\S*)"}}}
				return c
			}(),
			wantErr: "redaction_filters is not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}
