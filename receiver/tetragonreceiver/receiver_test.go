// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tetragonreceiver

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/open-telemetry/opentelemetry-collector-contrib/receiver/tetragonreceiver/internal/metadata"
	"github.com/cilium/tetragon/api/v1/tetragon"
)

type mockFineGuidanceSensorsServer struct {
	tetragon.UnimplementedFineGuidanceSensorsServer

	requestCh chan *tetragon.GetEventsRequest
	events    []*tetragon.GetEventsResponse
	recvDone  chan struct{}
}

func (s *mockFineGuidanceSensorsServer) GetEvents(req *tetragon.GetEventsRequest, stream grpc.ServerStreamingServer[tetragon.GetEventsResponse]) error {
	if s.requestCh != nil {
		s.requestCh <- req
		close(s.requestCh)
	}

	for _, ev := range s.events {
		if err := stream.Send(ev); err != nil {
			return err
		}
	}

	// Keep the stream open until the test cancels the context.
	<-stream.Context().Done()
	if s.recvDone != nil {
		close(s.recvDone)
	}
	return stream.Context().Err()
}

func startMockTetragonServer(t *testing.T) (net.Listener, *mockFineGuidanceSensorsServer) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	mock := &mockFineGuidanceSensorsServer{requestCh: make(chan *tetragon.GetEventsRequest, 1)}
	grpcServer := grpc.NewServer()
	tetragon.RegisterFineGuidanceSensorsServer(grpcServer, mock)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	return listener, mock
}

func TestGetEventsRequestFilterPropagation(t *testing.T) {
	listener, mock := startMockTetragonServer(t)

	cfg := createDefaultConfig().(*Config)
	cfg.ClientConfig = configgrpc.ClientConfig{
		Endpoint: listener.Addr().String(),
		TLS:      configtls.ClientConfig{Insecure: true},
	}
	cfg.AllowList = []FilterConfig{
		{EventSet: []string{"PROCESS_EXEC", "PROCESS_KPROBE"}, Namespace: []string{"prod"}},
	}
	cfg.DenyList = []FilterConfig{
		{HealthCheck: boolPtr(true)},
		{BinaryRegex: []string{"^/usr/bin/kubelet$"}},
	}
	cfg.FieldFilters = []FieldFilterConfig{
		{EventSet: []string{"PROCESS_EXEC"}, Fields: []string{"process.arguments"}, Action: "EXCLUDE"},
	}

	recv, err := newTetragonReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)

	require.NoError(t, recv.Start(t.Context(), componenttest.NewNopHost()))

	var req *tetragon.GetEventsRequest
	select {
	case req = <-mock.requestCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for GetEvents request")
	}
	require.Len(t, req.AllowList, 1)
	assert.Equal(t, []tetragon.EventType{tetragon.EventType_PROCESS_EXEC, tetragon.EventType_PROCESS_KPROBE}, req.AllowList[0].EventSet)
	assert.Equal(t, []string{"prod"}, req.AllowList[0].Namespace)

	require.Len(t, req.DenyList, 2)
	assert.Equal(t, wrapperspb.Bool(true), req.DenyList[0].HealthCheck)
	assert.Equal(t, []string{"^/usr/bin/kubelet$"}, req.DenyList[1].BinaryRegex)

	require.Len(t, req.FieldFilters, 1)
	assert.Equal(t, []tetragon.EventType{tetragon.EventType_PROCESS_EXEC}, req.FieldFilters[0].EventSet)
	assert.Equal(t, []string{"process.arguments"}, req.FieldFilters[0].Fields.GetPaths())
	assert.Equal(t, tetragon.FieldFilterAction_EXCLUDE, req.FieldFilters[0].Action)

	require.NoError(t, recv.Shutdown(t.Context()))
}

func TestReceiveEvents(t *testing.T) {
	listener, mock := startMockTetragonServer(t)
	mock.events = []*tetragon.GetEventsResponse{
		{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{Binary: "/bin/ls"},
				},
			},
		},
	}

	cfg := createDefaultConfig().(*Config)
	cfg.ClientConfig = configgrpc.ClientConfig{
		Endpoint: listener.Addr().String(),
		TLS:      configtls.ClientConfig{Insecure: true},
	}
	cfg.BufferSize = 100
	cfg.Workers = 1

	sink := new(consumertest.LogsSink)
	recv, err := newTetragonReceiver(receivertest.NewNopSettings(metadata.Type), cfg, sink)
	require.NoError(t, err)

	require.NoError(t, recv.Start(t.Context(), componenttest.NewNopHost()))

	require.Eventually(t, func() bool {
		return sink.LogRecordCount() >= 1
	}, 5*time.Second, 50*time.Millisecond)

	require.NoError(t, recv.Shutdown(t.Context()))

	require.Equal(t, 1, sink.LogRecordCount())
	lr := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Equal(t, "process_exec", lr.Body().AsString())
	assert.Equal(t, "/bin/ls", lr.Attributes().AsRaw()["process.executable.path"])
}

func boolPtr(b bool) *bool {
	return &b
}
