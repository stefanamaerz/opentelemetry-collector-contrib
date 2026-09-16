// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tetragonreceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/receiver/tetragonreceiver"

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/tetragonreceiver/internal/metadata"
	"github.com/cilium/tetragon/api/v1/tetragon"
)

// tetragonReceiver consumes Tetragon eBPF events over gRPC and emits OTel logs.
type tetragonReceiver struct {
	cfg      *Config
	settings receiver.Settings
	consumer consumer.Logs

	grpcClient *grpc.ClientConn

	eventsChan chan *eventWithReceiveTime
	stopWG     sync.WaitGroup
	cancel     context.CancelFunc

	telemetry *metadata.TelemetryBuilder
}

// eventWithReceiveTime pairs a Tetragon response with the time it was received.
type eventWithReceiveTime struct {
	resp         *tetragon.GetEventsResponse
	receivedAt   time.Time
}

// newTetragonReceiver creates a new tetragonReceiver.
func newTetragonReceiver(
	settings receiver.Settings,
	cfg *Config,
	consumer consumer.Logs,
) (*tetragonReceiver, error) {
	telemetryBuilder, err := metadata.NewTelemetryBuilder(settings.TelemetrySettings)
	if err != nil {
		return nil, fmt.Errorf("failed to create telemetry builder: %w", err)
	}

	return &tetragonReceiver{
		cfg:        cfg,
		settings:   settings,
		consumer:   consumer,
		eventsChan: make(chan *eventWithReceiveTime, cfg.BufferSize),
		telemetry:  telemetryBuilder,
	}, nil
}

// Start dials the Tetragon daemon and starts the stream reader and worker pool.
func (r *tetragonReceiver) Start(ctx context.Context, _ component.Host) error {
	clientConfig := r.cfg.ClientConfig
	grpcClient, err := clientConfig.ToClientConn(ctx, nil, r.settings.TelemetrySettings)
	if err != nil {
		return fmt.Errorf("failed to dial Tetragon: %w", err)
	}
	r.grpcClient = grpcClient

	tetragonClient := tetragon.NewFineGuidanceSensorsClient(grpcClient)

	ctx, cancel := context.WithCancel(ctx)
	r.cancel = cancel

	req := r.buildGetEventsRequest()
	stream, err := tetragonClient.GetEvents(ctx, req)
	if err != nil {
		_ = grpcClient.Close()
		r.grpcClient = nil
		r.cancel = nil
		return fmt.Errorf("failed to start Tetragon event stream: %w", err)
	}

	r.stopWG.Add(1 + r.cfg.Workers)
	go r.streamReader(ctx, stream)
	for i := 0; i < r.cfg.Workers; i++ {
		go r.worker(ctx)
	}

	return nil
}

// Shutdown stops the receiver and waits for goroutines to finish.
func (r *tetragonReceiver) Shutdown(ctx context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}
	done := make(chan struct{})
	go func() {
		r.stopWG.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}

	if r.grpcClient != nil {
		return r.grpcClient.Close()
	}
	return nil
}

// streamReader continuously receives events from the gRPC stream and pushes
// them onto the buffered events channel. If the channel is full, the event is
// dropped and a metric is incremented.
func (r *tetragonReceiver) streamReader(ctx context.Context, stream grpc.ServerStreamingClient[tetragon.GetEventsResponse]) {
	defer r.stopWG.Done()

	for {
		resp, err := stream.Recv()
		if err != nil {
			return
		}

		r.telemetry.TetragonreceiverEventsReceived.Add(ctx, 1)

		select {
		case r.eventsChan <- &eventWithReceiveTime{resp: resp, receivedAt: time.Now()}:
		default:
			r.telemetry.TetragonreceiverEventsDropped.Add(ctx, 1)
		}
	}
}

// worker reads events from the channel, converts them to plog.Logs, and
// forwards them to the next consumer.
func (r *tetragonReceiver) worker(ctx context.Context) {
	defer r.stopWG.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-r.eventsChan:
			logs := convertToOTelLogs(ev.resp, ev.receivedAt)
			if err := r.consumer.ConsumeLogs(ctx, logs); err != nil {
				r.telemetry.TetragonreceiverConsumeErrors.Add(ctx, 1)
				r.settings.Logger.Error("consume logs failed", zap.Error(err))
				continue
			}
		}
	}
}

// buildGetEventsRequest translates the user-friendly YAML configuration into
// the Tetragon protobuf GetEventsRequest.
func (r *tetragonReceiver) buildGetEventsRequest() *tetragon.GetEventsRequest {
	req := &tetragon.GetEventsRequest{
		AllowList:    make([]*tetragon.Filter, 0, len(r.cfg.AllowList)),
		DenyList:     make([]*tetragon.Filter, 0, len(r.cfg.DenyList)),
		FieldFilters: make([]*tetragon.FieldFilter, 0, len(r.cfg.FieldFilters)),
	}
	for _, f := range r.cfg.AllowList {
		req.AllowList = append(req.AllowList, filterConfigToProto(f))
	}
	for _, f := range r.cfg.DenyList {
		req.DenyList = append(req.DenyList, filterConfigToProto(f))
	}
	for _, f := range r.cfg.FieldFilters {
		req.FieldFilters = append(req.FieldFilters, fieldFilterConfigToProto(f))
	}
	return req
}

// filterConfigToProto converts a YAML FilterConfig into a Tetragon protobuf Filter.
func filterConfigToProto(f FilterConfig) *tetragon.Filter {
	pf := &tetragon.Filter{}
	if len(f.EventSet) > 0 {
		pf.EventSet = eventSetStringsToProto(f.EventSet)
	}
	if len(f.Namespace) > 0 {
		pf.Namespace = append([]string(nil), f.Namespace...)
	}
	if f.HealthCheck != nil {
		pf.HealthCheck = wrapperspb.Bool(*f.HealthCheck)
	}
	if len(f.BinaryRegex) > 0 {
		pf.BinaryRegex = append([]string(nil), f.BinaryRegex...)
	}
	return pf
}

// fieldFilterConfigToProto converts a YAML FieldFilterConfig into a Tetragon
// protobuf FieldFilter.
func fieldFilterConfigToProto(f FieldFilterConfig) *tetragon.FieldFilter {
	action := tetragon.FieldFilterAction_INCLUDE
	if strings.ToUpper(strings.TrimSpace(f.Action)) == "EXCLUDE" {
		action = tetragon.FieldFilterAction_EXCLUDE
	}
	pf := &tetragon.FieldFilter{
		Action: action,
		Fields: &fieldmaskpb.FieldMask{Paths: append([]string(nil), f.Fields...)},
	}
	if len(f.EventSet) > 0 {
		pf.EventSet = eventSetStringsToProto(f.EventSet)
	}
	return pf
}

func eventSetNameToType(name string) (tetragon.EventType, bool) {
	name = strings.ToUpper(strings.TrimSpace(name))
	v, ok := tetragon.EventType_value[name]
	if !ok {
		return tetragon.EventType_UNDEF, false
	}
	return tetragon.EventType(v), true
}

// eventSetStringsToProto maps strings to Tetragon EventType enum values.
func eventSetStringsToProto(values []string) []tetragon.EventType {
	result := make([]tetragon.EventType, 0, len(values))
	for _, v := range values {
		if et, ok := eventSetNameToType(v); ok {
			result = append(result, et)
		}
	}
	return result
}
