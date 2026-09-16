// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tetragonreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/tetragonreceiver"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/xreceiver"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/tetragonreceiver/internal/metadata"
)

// NewFactory creates a new receiver factory for Tetragon.
func NewFactory() receiver.Factory {
	return xreceiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		xreceiver.WithLogs(
			func(_ context.Context, params receiver.Settings, cfg component.Config, consumer consumer.Logs) (receiver.Logs, error) {
				return newTetragonReceiver(params, cfg.(*Config), consumer)
			},
			metadata.LogsStability,
		),
	)
}

func createDefaultConfig() component.Config {
	clientConfig := configgrpc.NewDefaultClientConfig()
	clientConfig.Endpoint = defaultEndpoint
	return &Config{
		ClientConfig: clientConfig,
		BufferSize:   defaultBufferSize,
		Workers:      defaultWorkers,
	}
}
