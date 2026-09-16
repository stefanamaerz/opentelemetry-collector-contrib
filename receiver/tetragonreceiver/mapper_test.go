// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tetragonreceiver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func TestEventBodyAndProcess(t *testing.T) {
	respExec := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{Binary: "/bin/cat"},
				Parent:  &tetragon.Process{Binary: "/bin/bash", Pid: wrapperspb.UInt32(1)},
			},
		},
	}

	body, process, parent := eventBodyAndProcess(respExec)
	assert.Equal(t, "process_exec", body)
	assert.Equal(t, "/bin/cat", process.Binary)
	assert.Equal(t, "/bin/bash", parent.Binary)
}

func TestConvertToOTelLogs(t *testing.T) {
	resp := &tetragon.GetEventsResponse{
		Time:     timestamppb.Now(),
		NodeName: "test-node",
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					ExecId:    "a:b:c",
					Pid:       wrapperspb.UInt32(42),
					Uid:       wrapperspb.UInt32(1000),
					Binary:    "/usr/bin/curl",
					Arguments: "example.com",
					Cwd:       "/home/user",
					Flags:     "execve",
					Pod: &tetragon.Pod{
						Namespace: "prod",
						Name:      "web-0",
						Container: &tetragon.Container{
							Id:   "container-id",
							Name: "web",
							Image: &tetragon.Image{
								Name: "nginx:latest",
							},
						},
					},
				},
				Parent: &tetragon.Process{
					ExecId: "parent-exec-id",
					Pid:    wrapperspb.UInt32(1),
					Binary: "/usr/lib/systemd/systemd",
				},
			},
		},
	}

	receivedAt := time.Unix(1234567890, 0)
	logs := convertToOTelLogs(resp, receivedAt)
	require.Equal(t, 1, logs.ResourceLogs().Len())
	rl := logs.ResourceLogs().At(0)
	res := rl.Resource()
	requireAttrStr(t, res.Attributes(), "service.name", "tetragon")
	requireAttrStr(t, res.Attributes(), "k8s.node.name", "test-node")

	sl := rl.ScopeLogs().At(0)
	require.Equal(t, 1, sl.LogRecords().Len())
	lr := sl.LogRecords().At(0)
	assert.Equal(t, "process_kprobe", lr.Body().AsString())
	assert.Equal(t, "INFO", lr.SeverityText())
	assert.Equal(t, pcommon.NewTimestampFromTime(receivedAt), lr.ObservedTimestamp())

	attrs := lr.Attributes()
	requireAttrStr(t, attrs, "tetragon.exec_id", "a:b:c")
	requireAttrInt(t, attrs, "process.pid", 42)
	requireAttrInt(t, attrs, "process.user.id", 1000)
	requireAttrStr(t, attrs, "process.executable.path", "/usr/bin/curl")
	requireAttrStr(t, attrs, "process.command_line", "example.com")
	requireAttrStr(t, attrs, "process.working_directory", "/home/user")
	requireAttrStr(t, attrs, "process.flags", "execve")
	requireAttrStr(t, attrs, "tetragon.parent.exec_id", "parent-exec-id")
	requireAttrInt(t, attrs, "process.parent_pid", 1)
	requireAttrStr(t, attrs, "process.parent.executable.path", "/usr/lib/systemd/systemd")
	requireAttrStr(t, attrs, "k8s.namespace.name", "prod")
	requireAttrStr(t, attrs, "k8s.pod.name", "web-0")
	requireAttrStr(t, attrs, "container.id", "container-id")
	requireAttrStr(t, attrs, "container.name", "web")
	requireAttrStr(t, attrs, "container.image.name", "nginx:latest")
}

func TestConvertToOTelLogsUnknownEvent(t *testing.T) {
	resp := &tetragon.GetEventsResponse{}
	logs := convertToOTelLogs(resp, time.Now())
	require.Equal(t, 1, logs.ResourceLogs().Len())
	lr := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Equal(t, "unknown", lr.Body().AsString())
}

func requireAttrStr(t *testing.T, attrs pcommon.Map, key, expected string) {
	t.Helper()
	v, ok := attrs.Get(key)
	require.True(t, ok, "expected attribute %q to be present", key)
	assert.Equal(t, expected, v.Str())
}

func requireAttrInt(t *testing.T, attrs pcommon.Map, key string, expected int64) {
	t.Helper()
	v, ok := attrs.Get(key)
	require.True(t, ok, "expected attribute %q to be present", key)
	assert.Equal(t, expected, v.Int())
}
