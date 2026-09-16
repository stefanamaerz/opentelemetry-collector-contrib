// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tetragonreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/tetragonreceiver"

import (
	"errors"
	"fmt"
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
)

const (
	defaultEndpoint   = "unix:///var/run/cilium/tetragon/tetragon.sock"
	defaultBufferSize = 10_000
	defaultWorkers    = 4
)

// FilterConfig defines a user-friendly YAML representation of a Tetragon
// Filter that is translated to a tetragon.Filter protobuf message in Start().
type FilterConfig struct {
	// EventSet filters on event types (e.g. PROCESS_EXEC, PROCESS_EXIT).
	EventSet []string `mapstructure:"event_set"`
	// Namespace filters on Kubernetes namespaces.
	Namespace []string `mapstructure:"namespace"`
	// HealthCheck matches health-check processes when true.
	HealthCheck *bool `mapstructure:"health_check"`
	// BinaryRegex filters on process binary paths using regexes.
	BinaryRegex []string `mapstructure:"binary_regex"`
}

// RedactionFilterConfig defines a user-friendly YAML representation of a
// Tetragon RedactionFilter.
type RedactionFilterConfig struct {
	// Redact is a list of regex patterns used to redact process arguments
	// and environment variables server-side.
	Redact []string `mapstructure:"redact"`
}

// FieldFilterConfig defines a user-friendly YAML representation of a Tetragon
// FieldFilter.
type FieldFilterConfig struct {
	// EventSet limits the filter to specific event types.
	EventSet []string `mapstructure:"event_set"`
	// Fields is the list of protobuf field paths to include or exclude.
	Fields []string `mapstructure:"fields"`
	// Action is either "INCLUDE" or "EXCLUDE".
	Action string `mapstructure:"action"`
}

// Config defines configuration for the Tetragon receiver.
type Config struct {
	// ClientConfig exposes the standard OTel gRPC client settings.
	// Endpoint defaults to the local Tetragon Unix Domain Socket.
	configgrpc.ClientConfig `mapstructure:",squash"`

	// BufferSize is the capacity of the channel between the gRPC stream
	// reader and the mapper worker pool.
	BufferSize int `mapstructure:"buffer_size"`
	// Workers is the number of goroutines that map Tetragon events into
	// plog.Logs and forward them to the next consumer.
	Workers int `mapstructure:"workers"`

	// AllowList switches the Tetragon stream to default-deny when populated.
	AllowList []FilterConfig `mapstructure:"allow_list"`
	// DenyList defines exclusion rules that take precedence over AllowList.
	DenyList []FilterConfig `mapstructure:"deny_list"`
	// RedactionFilters is currently unsupported: the Tetragon GetEvents API has
	// no redaction field, so the receiver cannot honor it. Validate() rejects a
	// non-empty value to avoid a false sense of security. Configure server-side
	// redaction in Tetragon itself (tracing-policy selectors, runtime
	// configuration, or the tetra CLI).
	RedactionFilters []RedactionFilterConfig `mapstructure:"redaction_filters"`
	// FieldFilters are protobuf field masks applied server-side by Tetragon.
	FieldFilters []FieldFilterConfig `mapstructure:"field_filters"`
}

var _ component.Config = (*Config)(nil)

// Validate checks the receiver configuration is valid.
func (cfg *Config) Validate() error {
	if cfg.Endpoint == "" {
		return errors.New("endpoint must be specified")
	}
	if cfg.BufferSize < 1 {
		return errors.New("buffer_size must be at least 1")
	}
	if cfg.Workers < 1 {
		return errors.New("workers must be at least 1")
	}
	for i, f := range cfg.FieldFilters {
		action := strings.ToUpper(strings.TrimSpace(f.Action))
		if action != "" && action != "INCLUDE" && action != "EXCLUDE" {
			return fmt.Errorf("field_filters[%d].action must be INCLUDE or EXCLUDE", i)
		}
		if err := validateEventSet(f.EventSet, fmt.Sprintf("field_filters[%d].event_set", i)); err != nil {
			return err
		}
	}
	for i, f := range cfg.AllowList {
		if err := validateEventSet(f.EventSet, fmt.Sprintf("allow_list[%d].event_set", i)); err != nil {
			return err
		}
	}
	for i, f := range cfg.DenyList {
		if err := validateEventSet(f.EventSet, fmt.Sprintf("deny_list[%d].event_set", i)); err != nil {
			return err
		}
	}
	if len(cfg.RedactionFilters) > 0 {
		return errors.New("redaction_filters is not supported: the Tetragon GetEvents API has no redaction field; " +
			"configure server-side redaction in Tetragon itself (tracing-policy selectors, runtime configuration, or the tetra CLI)")
	}
	return nil
}

func validateEventSet(values []string, path string) error {
	for _, v := range values {
		if _, ok := eventSetNameToType(strings.TrimSpace(v)); !ok {
			return fmt.Errorf("%s contains unknown event type %q", path, v)
		}
	}
	return nil
}
