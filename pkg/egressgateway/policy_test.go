// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressgateway

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/tables"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

func TestGatewayConfig_EgressIPWithoutInterface(t *testing.T) {
	tests := []struct {
		name     string
		egressIP string
		v4Needed bool
		v6Needed bool
		wantErr  bool
	}{
		{
			name:     "IPv4",
			egressIP: "192.0.2.123",
			v4Needed: true,
		},
		{
			name:     "IPv4 with IPv6 destinations",
			egressIP: "192.0.2.123",
			v4Needed: true,
			v6Needed: true,
			wantErr:  true,
		},
		{
			name:     "IPv6",
			egressIP: "2001:db8::123",
			v6Needed: true,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := statedb.New()
			devices, err := tables.NewDeviceTable(db)
			require.NoError(t, err)

			manager := &Manager{
				logger:      hivetest.Logger(t),
				db:          db,
				deviceTable: devices,
			}
			gc := policyGatewayConfig{egressIP: netip.MustParseAddr(tt.egressIP)}
			var gwc gatewayConfig
			err = gwc.deriveFromPolicyGatewayConfig(manager, &gc, tt.v4Needed, tt.v6Needed)
			if tt.wantErr {
				require.Error(t, err)
				assert.Equal(t, EgressIPNotFoundIPv4, gwc.egressIP4)
			} else {
				require.NoError(t, err)
				assert.Equal(t, gc.egressIP, gwc.egressIP4)
			}
			assert.Equal(t, EgressIPNotFoundIPv6, gwc.egressIP6)
			assert.Empty(t, gwc.ifaceName)
			assert.Zero(t, gwc.egressIfindex)
			assert.False(t, gwc.localNodeConfiguredAsGateway)
		})
	}
}

func TestGatewayConfig_EgressIPOnDevice(t *testing.T) {
	db := statedb.New()
	devices, err := tables.NewDeviceTable(db)
	require.NoError(t, err)
	nodeAddresses, err := tables.NewNodeAddressTable(db)
	require.NoError(t, err)

	ip4 := netip.MustParseAddr("192.0.2.1")
	ip6 := netip.MustParseAddr("2001:db8::1")
	dev := &tables.Device{
		Index: 1,
		Name:  "egress-test",
		Addrs: []tables.DeviceAddress{{Addr: ip4}, {Addr: ip6}},
	}
	txn := db.WriteTxn(devices, nodeAddresses)
	_, _, err = devices.Insert(txn, dev)
	require.NoError(t, err)
	for _, ip := range []netip.Addr{ip4, ip6} {
		_, _, err = nodeAddresses.Insert(txn, tables.NodeAddress{
			Addr:       ip,
			Primary:    true,
			DeviceName: dev.Name,
		})
		require.NoError(t, err)
	}
	txn.Commit()

	manager := &Manager{
		logger:        hivetest.Logger(t),
		db:            db,
		deviceTable:   devices,
		nodeAddrTable: nodeAddresses,
	}
	for _, ip := range []netip.Addr{ip4, ip6} {
		t.Run(ip.String(), func(t *testing.T) {
			gc := policyGatewayConfig{egressIP: ip}
			var gwc gatewayConfig
			require.NoError(t, gwc.deriveFromPolicyGatewayConfig(manager, &gc, true, true))
			assert.Equal(t, ip4, gwc.egressIP4)
			assert.Equal(t, ip6, gwc.egressIP6)
			assert.Equal(t, dev.Name, gwc.ifaceName)
			assert.True(t, gwc.localNodeConfiguredAsGateway)
		})
	}
}

func getAsPolicyLabelSelectors(k8sLss []*slimv1.LabelSelector) (lss []*policyTypes.LabelSelector) {
	for _, ls := range k8sLss {
		lss = append(lss, policyTypes.NewLabelSelector(api.NewESFromK8sLabelSelector(labels.LabelSourceK8sKeyPrefix, ls)))
	}
	return lss
}

func TestPolicyConfig_updateMatchedEndpointIDs(t *testing.T) {
	type fields struct {
		id                types.NamespacedName
		endpointSelectors []*slimv1.LabelSelector
		nodeSelectors     []*slimv1.LabelSelector
		dstCIDRs          []netip.Prefix
		excludedCIDRs     []netip.Prefix
		policyGwConfigs   []policyGatewayConfig
		matchedEndpoints  map[endpointID]*endpointMetadata
		gatewayConfigs    []gatewayConfig
	}
	type args struct {
		epDataStore           map[endpointID]*endpointMetadata
		nodesAddresses2Labels map[string]map[string]string
	}
	tests := []struct {
		name           string
		fields         fields
		args           args
		want           int
		wantEndpointID endpointID
	}{
		{
			name: "Test updateMatchedEndpointIDs with endpoints and nodes",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"app": "test",
					},
				}},
				nodeSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"node-name": "node1",
					},
				}},
			},
			args: args{
				epDataStore: map[endpointID]*endpointMetadata{
					"123456": {
						id: "123456",
						labels: map[string]string{
							"app": "test",
						},
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.10": {
						"node-name": "node1",
					},
				},
			},
			want:           1,
			wantEndpointID: endpointID("123456"),
		},
		{
			name: "Test updateMatchedEndpointIDs with namespaced endpoints and nodes",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"io.kubernetes.pod.namespace": "default",
						"app":                         "test",
					},
				}},
				nodeSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"node-name": "node1",
					},
				}},
			},
			args: args{
				epDataStore: map[endpointID]*endpointMetadata{
					"123456": {
						id: "123456",
						labels: map[string]string{
							"io.kubernetes.pod.namespace": "default",
							"app":                         "test",
						},
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.10": {
						"node-name": "node1",
					},
				},
			},
			want:           1,
			wantEndpointID: endpointID("123456"),
		},
		{
			name: "Test updateMatchedEndpointIDs endpoints and nodes with no match",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"app": "test",
					},
				}},
				nodeSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"node-name": "node1",
					},
				}},
			},
			args: args{
				epDataStore: map[endpointID]*endpointMetadata{
					"123456": {
						id: "123456",
						labels: map[string]string{
							"app": "test",
						},
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.11": {
						"node-name": "node1",
					},
				},
			},
			want:           0,
			wantEndpointID: "",
		},
		{
			name: "Test updateMatchedEndpointIDs endpoints and nodes with no match label",
			fields: fields{
				id: types.NamespacedName{
					Name: "test",
				},
				endpointSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"app": "test",
					},
				}},
				nodeSelectors: []*slimv1.LabelSelector{{
					MatchLabels: map[string]string{
						"node-name": "node1",
					},
				}},
			},
			args: args{
				epDataStore: map[endpointID]*endpointMetadata{
					"123456": {
						id: "123456",
						labels: map[string]string{
							"app": "test",
						},
						nodeIP: "192.168.1.10",
					},
				},
				nodesAddresses2Labels: map[string]map[string]string{
					"192.168.1.10": {
						"bar": "bar",
					},
				},
			},
			want:           0,
			wantEndpointID: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &PolicyConfig{
				id:                tt.fields.id,
				endpointSelectors: getAsPolicyLabelSelectors(tt.fields.endpointSelectors),
				nodeSelectors:     getAsPolicyLabelSelectors(tt.fields.nodeSelectors),
				dstCIDRs:          tt.fields.dstCIDRs,
				excludedCIDRs:     tt.fields.excludedCIDRs,
				policyGwConfigs:   tt.fields.policyGwConfigs,
				matchedEndpoints:  tt.fields.matchedEndpoints,
				gatewayConfigs:    tt.fields.gatewayConfigs,
			}
			config.updateMatchedEndpointIDs(tt.args.epDataStore, tt.args.nodesAddresses2Labels)
			assert.Len(t, config.matchedEndpoints, tt.want)
			if tt.want > 0 {
				assert.Contains(t, config.matchedEndpoints, endpointID(tt.wantEndpointID))
			}
		})
	}
}
