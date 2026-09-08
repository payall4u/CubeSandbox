//go:build linux

// Copyright (c) 2024 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

package runtimeresource

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tencentcloud/CubeSandbox/Cubelet/services/runtime/state"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type fakeNetlinkExecutor struct {
	handle *fakeNetlinkHandle
	paths  []string
}

func (e *fakeNetlinkExecutor) Run(ctx context.Context, path string, operation func(netlinkHandle) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.paths = append(e.paths, path)
	return operation(e.handle)
}

type fakeNetlinkHandle struct {
	links           map[string]netlink.Link
	addresses       []netlink.Addr
	routes          map[int][]netlink.Route
	neighbors       []netlink.Neigh
	neighborReads   int
	qdiscs          map[int][]netlink.Qdisc
	filters         map[int][]netlink.Filter
	operations      []string
	nextLinkIndex   int
	addrListErrors  []error
	failOperation   string
	failError       error
	failCounts      map[string]int
	eventualNeigh   []netlink.Neigh
	neighAfterRead  int
	linkReadyAfter  int
	linkReads       int
	addrReadyAfter  int
	addrReads       int
	routeReadyAfter int
	routeReads      int
}

func newFakeNetlinkHandle() *fakeNetlinkHandle {
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	return &fakeNetlinkHandle{
		links: map[string]netlink.Link{
			"eth0": &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 1, MTU: 1450, HardwareAddr: mac}},
		},
		routes: make(map[int][]netlink.Route), qdiscs: make(map[int][]netlink.Qdisc), filters: make(map[int][]netlink.Filter), nextLinkIndex: 2,
	}
}

func (h *fakeNetlinkHandle) record(operation string) error {
	h.operations = append(h.operations, operation)
	if h.failCounts[operation] > 0 {
		h.failCounts[operation]--
		return errors.New("injected counted failure at " + operation)
	}
	if h.failOperation == operation {
		h.failOperation = ""
		if h.failError != nil {
			return h.failError
		}
		return errors.New("injected netlink failure")
	}
	return nil
}

func (h *fakeNetlinkHandle) LinkByName(name string) (netlink.Link, error) {
	if err := h.record("link-get " + name); err != nil {
		return nil, err
	}
	if name == "eth0" {
		h.linkReads++
		if h.linkReadyAfter > 0 && h.linkReads < h.linkReadyAfter {
			return nil, unix.ENODEV
		}
	}
	link, ok := h.links[name]
	if !ok {
		return nil, unix.ENODEV
	}
	return link, nil
}

func (h *fakeNetlinkHandle) LinkAdd(link netlink.Link) error {
	if err := h.record(fmt.Sprintf("link-add %s %s", link.Attrs().Name, link.Type())); err != nil {
		return err
	}
	if _, exists := h.links[link.Attrs().Name]; exists {
		return unix.EEXIST
	}
	link.Attrs().Index = h.nextLinkIndex
	h.nextLinkIndex++
	h.links[link.Attrs().Name] = link
	return nil
}

func (h *fakeNetlinkHandle) LinkDel(link netlink.Link) error {
	if err := h.record("link-del " + link.Attrs().Name); err != nil {
		return err
	}
	delete(h.links, link.Attrs().Name)
	return nil
}

func (h *fakeNetlinkHandle) LinkSetMTU(link netlink.Link, mtu int) error {
	if err := h.record(fmt.Sprintf("link-mtu %s %d", link.Attrs().Name, mtu)); err != nil {
		return err
	}
	link.Attrs().MTU = mtu
	return nil
}

func (h *fakeNetlinkHandle) LinkSetUp(link netlink.Link) error {
	if err := h.record("link-up " + link.Attrs().Name); err != nil {
		return err
	}
	link.Attrs().Flags |= net.FlagUp
	return nil
}

func (h *fakeNetlinkHandle) LinkSetAlias(link netlink.Link, alias string) error {
	if err := h.record("link-alias " + link.Attrs().Name + " " + alias); err != nil {
		return err
	}
	link.Attrs().Alias = alias
	return nil
}

func (h *fakeNetlinkHandle) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	if err := h.record(fmt.Sprintf("addr-list %s %d", link.Attrs().Name, family)); err != nil {
		return nil, err
	}
	if len(h.addrListErrors) != 0 {
		err := h.addrListErrors[0]
		h.addrListErrors = h.addrListErrors[1:]
		if err != nil {
			return nil, err
		}
	}
	h.addrReads++
	if h.addrReadyAfter > 0 && h.addrReads < h.addrReadyAfter {
		return nil, nil
	}
	return slices.Clone(h.addresses), nil
}

func (h *fakeNetlinkHandle) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	if err := h.record(fmt.Sprintf("route-list %s %d", link.Attrs().Name, family)); err != nil {
		return nil, err
	}
	h.routeReads++
	if h.routeReadyAfter > 0 && h.routeReads < h.routeReadyAfter {
		return nil, nil
	}
	return slices.Clone(h.routes[family]), nil
}

func (h *fakeNetlinkHandle) NeighList(index, family int) ([]netlink.Neigh, error) {
	if err := h.record(fmt.Sprintf("neighbor-list %d %d", index, family)); err != nil {
		return nil, err
	}
	h.neighborReads++
	if h.neighAfterRead > 0 && h.neighborReads >= h.neighAfterRead {
		return slices.Clone(h.eventualNeigh), nil
	}
	return slices.Clone(h.neighbors), nil
}

func (h *fakeNetlinkHandle) QdiscList(link netlink.Link) ([]netlink.Qdisc, error) {
	if err := h.record("qdisc-list " + link.Attrs().Name); err != nil {
		return nil, err
	}
	return slices.Clone(h.qdiscs[link.Attrs().Index]), nil
}

func (h *fakeNetlinkHandle) QdiscAdd(qdisc netlink.Qdisc) error {
	if err := h.record(fmt.Sprintf("qdisc-add %d %s", qdisc.Attrs().LinkIndex, qdisc.Type())); err != nil {
		return err
	}
	h.qdiscs[qdisc.Attrs().LinkIndex] = append(h.qdiscs[qdisc.Attrs().LinkIndex], qdisc)
	return nil
}

func (h *fakeNetlinkHandle) FilterList(link netlink.Link, parent uint32) ([]netlink.Filter, error) {
	if err := h.record(fmt.Sprintf("filter-list %s %x", link.Attrs().Name, parent)); err != nil {
		return nil, err
	}
	var result []netlink.Filter
	for _, filter := range h.filters[link.Attrs().Index] {
		if filter.Attrs().Parent == parent {
			result = append(result, filter)
		}
	}
	return result, nil
}

func (h *fakeNetlinkHandle) FilterReplace(filter netlink.Filter) error {
	if err := h.record(fmt.Sprintf("filter-replace %d %d", filter.Attrs().LinkIndex, filter.Attrs().Priority)); err != nil {
		return err
	}
	filters := h.filters[filter.Attrs().LinkIndex]
	for index, existing := range filters {
		if existing.Attrs().Priority == filter.Attrs().Priority {
			filters[index] = filter
			h.filters[filter.Attrs().LinkIndex] = filters
			return nil
		}
	}
	h.filters[filter.Attrs().LinkIndex] = append(filters, filter)
	return nil
}

func (h *fakeNetlinkHandle) FilterDel(filter netlink.Filter) error {
	if err := h.record(fmt.Sprintf("filter-del %d %d", filter.Attrs().LinkIndex, filter.Attrs().Priority)); err != nil {
		return err
	}
	filters := h.filters[filter.Attrs().LinkIndex]
	for index, existing := range filters {
		if existing == filter {
			h.filters[filter.Attrs().LinkIndex] = append(filters[:index], filters[index+1:]...)
			return nil
		}
	}
	return unix.ENOENT
}

func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	network.IP = ip
	return network
}

func configureFakeDualStack(t *testing.T, handle *fakeNetlinkHandle) {
	t.Helper()
	handle.addresses = []netlink.Addr{
		{IPNet: mustCIDR(t, "10.0.0.2/24"), Scope: unix.RT_SCOPE_UNIVERSE},
		{IPNet: mustCIDR(t, "fe80::2/64"), Scope: unix.RT_SCOPE_LINK},
		{IPNet: mustCIDR(t, "2001:db8::2/64"), Scope: unix.RT_SCOPE_UNIVERSE},
	}
	handle.routes[netlink.FAMILY_V4] = []netlink.Route{
		{LinkIndex: 1, Table: unix.RT_TABLE_MAIN, Gw: net.ParseIP("10.0.0.1"), Src: net.ParseIP("10.0.0.2"), Scope: netlink.SCOPE_UNIVERSE},
		{LinkIndex: 1, Table: unix.RT_TABLE_MAIN, Dst: mustCIDR(t, "10.0.0.0/24"), Scope: netlink.SCOPE_LINK},
		{LinkIndex: 1, Table: unix.RT_TABLE_LOCAL, Dst: mustCIDR(t, "10.0.0.2/32"), Scope: netlink.SCOPE_HOST},
	}
	handle.routes[netlink.FAMILY_V6] = []netlink.Route{
		{LinkIndex: 1, Table: unix.RT_TABLE_MAIN, Gw: net.ParseIP("fe80::1"), Src: net.ParseIP("2001:db8::2"), Scope: netlink.SCOPE_UNIVERSE},
		{LinkIndex: 1, Table: unix.RT_TABLE_MAIN, Dst: mustCIDR(t, "2001:db8::/64"), Scope: netlink.SCOPE_LINK},
	}
	mac4, _ := net.ParseMAC("02:00:00:00:00:04")
	mac6, _ := net.ParseMAC("02:00:00:00:00:06")
	handle.neighbors = []netlink.Neigh{
		{LinkIndex: 1, IP: net.ParseIP("10.0.0.1"), HardwareAddr: mac4, State: netlink.NUD_REACHABLE},
		{LinkIndex: 1, IP: net.ParseIP("fe80::1"), HardwareAddr: mac6, State: netlink.NUD_STALE},
	}
}

func TestNodeNetworkBackendSelection(t *testing.T) {
	for _, test := range []struct {
		name, value, want string
		wantError         bool
	}{
		{name: "default", want: "netlink"},
		{name: "explicit netlink", value: " NeTlInK ", want: "netlink"},
		{name: "command rollback", value: "command", want: "command"},
		{name: "invalid", value: "automatic", wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(networkBackendEnvironment, test.value)
			network, err := newNodeNetwork()
			if test.wantError {
				if err == nil || !strings.Contains(err.Error(), networkBackendEnvironment) {
					t.Fatalf("network=%T error=%v", network, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			switch network.(type) {
			case *netlinkNetwork:
				if test.want != "netlink" {
					t.Fatalf("network=%T, want %s", network, test.want)
				}
			case *linuxNetwork:
				if test.want != "command" {
					t.Fatalf("network=%T, want %s", network, test.want)
				}
			default:
				t.Fatalf("network=%T", network)
			}
		})
	}
}

func TestNetlinkNetworkPrepareBuildsDualStackAttachmentWithoutCommands(t *testing.T) {
	handle := newFakeNetlinkHandle()
	configureFakeDualStack(t, handle)
	executor := &fakeNetlinkExecutor{handle: handle}
	network := &netlinkNetwork{executor: executor, probe: func(context.Context, string, net.IP) error {
		t.Fatal("gateway probe called with populated neighbor table")
		return nil
	}}
	netnsPath := t.TempDir()
	attachment, err := network.Prepare(context.Background(), netnsPath, "eth0", "cb123")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(executor.paths, []string{netnsPath}) {
		t.Fatalf("namespace paths=%v", executor.paths)
	}
	if attachment.GetMac() != "02:00:00:00:00:01" || attachment.GetMtu() != 1450 ||
		!slices.Equal(attachment.GetIps(), []string{"10.0.0.2/24", "2001:db8::2/64"}) ||
		len(attachment.GetRoutes()) != 6 || len(attachment.GetNeighbors()) != 2 {
		t.Fatalf("attachment=%+v", attachment)
	}
	tap, ok := handle.links["cb123"].(*netlink.Tuntap)
	if !ok || tap.Mode != netlink.TUNTAP_MODE_TAP || tap.Queues != 1 ||
		tap.Flags&(netlink.TUNTAP_MULTI_QUEUE|netlink.TUNTAP_VNET_HDR|netlink.TUNTAP_NO_PI) !=
			netlink.TUNTAP_MULTI_QUEUE|netlink.TUNTAP_VNET_HDR|netlink.TUNTAP_NO_PI ||
		tap.Attrs().MTU != 1450 || tap.Attrs().Flags&net.FlagUp == 0 {
		t.Fatalf("tap=%+v", tap)
	}
	for _, link := range []netlink.Link{handle.links["eth0"], handle.links["cb123"]} {
		qdiscs := handle.qdiscs[link.Attrs().Index]
		if len(qdiscs) != 1 || qdiscs[0].Type() != "ingress" {
			t.Fatalf("link=%s qdiscs=%+v", link.Attrs().Name, qdiscs)
		}
		filters := handle.filters[link.Attrs().Index]
		if len(filters) != 1 || filters[0].Attrs().Priority != tcPriority || filters[0].Attrs().Protocol != unix.ETH_P_ALL {
			t.Fatalf("link=%s filters=%+v", link.Attrs().Name, filters)
		}
		u32, ok := filters[0].(*netlink.U32)
		if !ok || len(u32.Actions) != 1 {
			t.Fatalf("link=%s filter=%+v", link.Attrs().Name, filters[0])
		}
		mirred, ok := u32.Actions[0].(*netlink.MirredAction)
		wantTarget := 2
		if link.Attrs().Index == 2 {
			wantTarget = 1
		}
		if !ok || mirred.MirredAction != netlink.TCA_EGRESS_REDIR || mirred.Ifindex != wantTarget {
			t.Fatalf("link=%s action=%+v", link.Attrs().Name, u32.Actions[0])
		}
	}
	wantRoutes := []struct {
		destination, gateway, source string
		scope                        uint32
	}{
		{"10.0.0.1/32", "", "10.0.0.2", unix.RT_SCOPE_LINK},
		{"0.0.0.0/0", "10.0.0.1", "10.0.0.2", unix.RT_SCOPE_UNIVERSE},
		{"10.0.0.0/24", "", "10.0.0.2", unix.RT_SCOPE_LINK},
		{"fe80::1/128", "", "2001:db8::2", unix.RT_SCOPE_LINK},
		{"::/0", "fe80::1", "2001:db8::2", unix.RT_SCOPE_UNIVERSE},
		{"2001:db8::/64", "", "2001:db8::2", unix.RT_SCOPE_LINK},
	}
	for index, want := range wantRoutes {
		route := attachment.GetRoutes()[index]
		if route.GetDestination() != want.destination || route.GetGateway() != want.gateway ||
			route.GetSource() != want.source || route.GetDevice() != "eth0" || route.GetScope() != want.scope {
			t.Fatalf("route[%d]=%+v want=%+v", index, route, want)
		}
	}
	joined := strings.Join(handle.operations, "\n")
	if strings.Index(joined, "neighbor-list") > strings.Index(joined, "filter-replace") {
		t.Fatalf("neighbors must be captured before redirect filters:\n%s", joined)
	}
}

func TestNetlinkNetworkWaitsForCNIInterfaceAddressAndRoute(t *testing.T) {
	handle := newFakeNetlinkHandle()
	configureFakeDualStack(t, handle)
	handle.linkReadyAfter = 3
	handle.addrReadyAfter = 3
	handle.routeReadyAfter = 2
	network := &netlinkNetwork{executor: &fakeNetlinkExecutor{handle: handle}, probe: func(context.Context, string, net.IP) error {
		t.Fatal("gateway probe called with populated neighbor table")
		return nil
	}}
	attachment, err := network.Prepare(context.Background(), t.TempDir(), "eth0", "cb123")
	if err != nil {
		t.Fatal(err)
	}
	if attachment.GetMac() == "" || len(attachment.GetIps()) != 2 || len(attachment.GetRoutes()) == 0 {
		t.Fatalf("attachment=%+v", attachment)
	}
	if handle.linkReads < 5 || handle.addrReads < 3 || handle.routeReads < 2 {
		t.Fatalf("readiness polls link=%d addr=%d route=%d", handle.linkReads, handle.addrReads, handle.routeReads)
	}
}

func TestNetlinkNetworkReadinessWaitHonorsContext(t *testing.T) {
	handle := newFakeNetlinkHandle()
	handle.linkReadyAfter = 1_000_000
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Millisecond)
	defer cancel()
	network := &netlinkNetwork{executor: &fakeNetlinkExecutor{handle: handle}, probe: probeGatewayUDP}
	_, err := network.Prepare(ctx, t.TempDir(), "eth0", "cb123")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v, want context deadline", err)
	}
	if _, exists := handle.links["cb123"]; exists {
		t.Fatal("TAP was created before CNI configuration became ready")
	}
}

func TestNetlinkNetworkProbesOnlyMissingGateway(t *testing.T) {
	handle := newFakeNetlinkHandle()
	configureFakeDualStack(t, handle)
	handle.neighbors = handle.neighbors[:1]
	probes := make([]string, 0, 1)
	network := &netlinkNetwork{executor: &fakeNetlinkExecutor{handle: handle}, probe: func(_ context.Context, device string, gateway net.IP) error {
		probes = append(probes, device+"/"+gateway.String())
		mac, _ := net.ParseMAC("02:00:00:00:00:06")
		handle.neighbors = append(handle.neighbors, netlink.Neigh{LinkIndex: 1, IP: gateway, HardwareAddr: mac, State: netlink.NUD_REACHABLE})
		return nil
	}}
	attachment, err := network.Prepare(context.Background(), t.TempDir(), "eth0", "cb123")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(probes, []string{"eth0/fe80::1"}) || handle.neighborReads != 2 || len(attachment.GetNeighbors()) != 2 {
		t.Fatalf("probes=%v reads=%d neighbors=%+v", probes, handle.neighborReads, attachment.GetNeighbors())
	}
}

func TestNetlinkNetworkPollsAfterAsynchronousGatewayProbe(t *testing.T) {
	handle := newFakeNetlinkHandle()
	configureFakeDualStack(t, handle)
	handle.eventualNeigh = slices.Clone(handle.neighbors)
	handle.neighbors = nil
	handle.neighAfterRead = 4
	var probes []string
	network := &netlinkNetwork{executor: &fakeNetlinkExecutor{handle: handle}, probe: func(_ context.Context, device string, gateway net.IP) error {
		probes = append(probes, device+"/"+gateway.String())
		return nil
	}}
	attachment, err := network.Prepare(context.Background(), t.TempDir(), "eth0", "cb123")
	if err != nil {
		t.Fatal(err)
	}
	if handle.neighborReads != 4 || len(attachment.GetNeighbors()) != 2 {
		t.Fatalf("reads=%d neighbors=%+v", handle.neighborReads, attachment.GetNeighbors())
	}
	if !slices.Contains(probes, "eth0/10.0.0.1") || !slices.Contains(probes, "eth0/fe80::1") {
		t.Fatalf("probes=%v", probes)
	}
}

func TestNetlinkNetworkUsesClsactIngressParentForCreateAndRelease(t *testing.T) {
	handle := newFakeNetlinkHandle()
	configureFakeDualStack(t, handle)
	handle.qdiscs[1] = []netlink.Qdisc{&netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: 1, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT,
	}}}
	network := &netlinkNetwork{executor: &fakeNetlinkExecutor{handle: handle}, probe: func(context.Context, string, net.IP) error { return nil }}
	if _, err := network.Prepare(context.Background(), t.TempDir(), "eth0", "cb123"); err != nil {
		t.Fatal(err)
	}
	cniFilters := handle.filters[1]
	tapFilters := handle.filters[2]
	if len(cniFilters) != 1 || cniFilters[0].Attrs().Parent != netlink.HANDLE_MIN_INGRESS {
		t.Fatalf("CNI filters=%+v", cniFilters)
	}
	if len(tapFilters) != 1 || tapFilters[0].Attrs().Parent != netlink.MakeHandle(0xffff, 0) {
		t.Fatalf("TAP filters=%+v", tapFilters)
	}
	if err := network.Release(context.Background(), t.TempDir(), "eth0", "cb123"); err != nil {
		t.Fatal(err)
	}
	if len(handle.filters[1]) != 0 || len(handle.filters[2]) != 0 {
		t.Fatalf("filters after release: cni=%+v tap=%+v", handle.filters[1], handle.filters[2])
	}
}

func TestNetlinkNetworkReleaseDeletesReservedFiltersAndTapOnly(t *testing.T) {
	handle := newFakeNetlinkHandle()
	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: "cb123", Index: 2, Alias: tapOwnershipAlias("cb123")}, Mode: netlink.TUNTAP_MODE_TAP,
		Flags: netlink.TUNTAP_MULTI_QUEUE_DEFAULTS | netlink.TUNTAP_VNET_HDR,
	}
	handle.links["cb123"] = tap
	for _, link := range []netlink.Link{handle.links["eth0"], tap} {
		handle.qdiscs[link.Attrs().Index] = []netlink.Qdisc{&netlink.Ingress{QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_INGRESS,
		}}}
		handle.filters[link.Attrs().Index] = []netlink.Filter{
			&netlink.U32{FilterAttrs: netlink.FilterAttrs{LinkIndex: link.Attrs().Index, Parent: netlink.MakeHandle(0xffff, 0), Priority: 7}},
			&netlink.U32{FilterAttrs: netlink.FilterAttrs{LinkIndex: link.Attrs().Index, Parent: netlink.MakeHandle(0xffff, 0), Priority: tcPriority}},
		}
	}
	network := &netlinkNetwork{executor: &fakeNetlinkExecutor{handle: handle}, probe: probeGatewayUDP}
	if err := network.Release(context.Background(), t.TempDir(), "eth0", "cb123"); err != nil {
		t.Fatal(err)
	}
	if err := network.Release(context.Background(), t.TempDir(), "eth0", "cb123"); err != nil {
		t.Fatalf("idempotent release: %v", err)
	}
	if _, exists := handle.links["cb123"]; exists {
		t.Fatal("TAP still exists")
	}
	for _, index := range []int{1, 2} {
		filters := handle.filters[index]
		if len(filters) != 1 || filters[0].Attrs().Priority != 7 {
			t.Fatalf("link index=%d filters=%+v", index, filters)
		}
	}
}

func TestNetlinkDumpRetriesInterruptedReads(t *testing.T) {
	handle := newFakeNetlinkHandle()
	handle.addresses = []netlink.Addr{{IPNet: mustCIDR(t, "10.0.0.2/24"), Scope: unix.RT_SCOPE_UNIVERSE}}
	handle.addrListErrors = []error{netlink.ErrDumpInterrupted, unix.EINTR, nil}
	addresses, err := netlinkAddresses(context.Background(), handle, handle.links["eth0"])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(addresses, []string{"10.0.0.2/24"}) {
		t.Fatalf("addresses=%v", addresses)
	}
}

func TestNetlinkNetworkRejectsNonTapNameCollision(t *testing.T) {
	handle := newFakeNetlinkHandle()
	configureFakeDualStack(t, handle)
	handle.links["cb123"] = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "cb123", Index: 2}}
	network := &netlinkNetwork{executor: &fakeNetlinkExecutor{handle: handle}, probe: probeGatewayUDP}
	_, err := network.Prepare(context.Background(), t.TempDir(), "eth0", "cb123")
	if err == nil || !strings.Contains(err.Error(), "want tuntap") {
		t.Fatalf("error=%v", err)
	}
}

func TestNetlinkNetworkRejectsIncompatibleExistingTuntapWithoutDeletingIt(t *testing.T) {
	requiredFlags := netlink.TUNTAP_MULTI_QUEUE_DEFAULTS | netlink.TUNTAP_VNET_HDR
	for _, test := range []struct {
		name       string
		mode       netlink.TuntapMode
		flags      netlink.TuntapFlag
		nonPersist bool
		want       string
	}{
		{name: "tun mode", mode: netlink.TUNTAP_MODE_TUN, flags: requiredFlags, want: "want tap"},
		{name: "single queue", mode: netlink.TUNTAP_MODE_TAP, flags: netlink.TUNTAP_VNET_HDR | netlink.TUNTAP_NO_PI, want: "multi_queue"},
		{name: "missing vnet header", mode: netlink.TUNTAP_MODE_TAP, flags: netlink.TUNTAP_MULTI_QUEUE_DEFAULTS, want: "vnet_hdr"},
		{name: "packet info enabled", mode: netlink.TUNTAP_MODE_TAP, flags: netlink.TUNTAP_MULTI_QUEUE | netlink.TUNTAP_VNET_HDR, want: "no_pi"},
		{name: "non persistent", mode: netlink.TUNTAP_MODE_TAP, flags: requiredFlags, nonPersist: true, want: "non-persistent"},
	} {
		t.Run(test.name, func(t *testing.T) {
			handle := newFakeNetlinkHandle()
			configureFakeDualStack(t, handle)
			tap := &netlink.Tuntap{
				LinkAttrs: netlink.LinkAttrs{Name: "cb123", Index: 2, Alias: tapOwnershipAlias("cb123")}, Mode: test.mode,
				Flags: test.flags, NonPersist: test.nonPersist,
			}
			handle.links["cb123"] = tap
			for _, link := range []netlink.Link{handle.links["eth0"], tap} {
				handle.qdiscs[link.Attrs().Index] = []netlink.Qdisc{&netlink.Ingress{QdiscAttrs: netlink.QdiscAttrs{
					LinkIndex: link.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_INGRESS,
				}}}
				handle.filters[link.Attrs().Index] = []netlink.Filter{&netlink.U32{FilterAttrs: netlink.FilterAttrs{
					LinkIndex: link.Attrs().Index, Parent: netlink.MakeHandle(0xffff, 0), Priority: tcPriority,
				}}}
			}
			network := &netlinkNetwork{executor: &fakeNetlinkExecutor{handle: handle}, probe: probeGatewayUDP}
			_, err := network.Prepare(context.Background(), t.TempDir(), "eth0", "cb123")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Prepare error=%v want substring %q", err, test.want)
			}
			if err := network.Release(context.Background(), t.TempDir(), "eth0", "cb123"); err == nil || !strings.Contains(err.Error(), "refuse TAP release") {
				t.Fatalf("Release error=%v", err)
			}
			if handle.links["cb123"] != tap {
				t.Fatal("incompatible pre-existing TUN/TAP was deleted")
			}
			for _, index := range []int{1, 2} {
				filters := handle.filters[index]
				if len(filters) != 1 || filters[0].Attrs().Priority != tcPriority {
					t.Fatalf("filters on index %d changed: %+v", index, filters)
				}
			}
		})
	}
}

func TestNetlinkNetworkRecoversCompatiblePersistentTap(t *testing.T) {
	handle := newFakeNetlinkHandle()
	configureFakeDualStack(t, handle)
	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: "cb123", Index: 2, MTU: 1200, Alias: tapOwnershipAlias("cb123")}, Mode: netlink.TUNTAP_MODE_TAP,
		Flags: netlink.TUNTAP_MULTI_QUEUE_DEFAULTS | netlink.TUNTAP_VNET_HDR,
	}
	handle.links["cb123"] = tap
	for _, link := range []netlink.Link{handle.links["eth0"], tap} {
		handle.qdiscs[link.Attrs().Index] = []netlink.Qdisc{&netlink.Ingress{QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_INGRESS,
		}}}
		handle.filters[link.Attrs().Index] = []netlink.Filter{&netlink.U32{FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index, Parent: netlink.MakeHandle(0xffff, 0), Priority: tcPriority,
		}}}
	}
	network := &netlinkNetwork{executor: &fakeNetlinkExecutor{handle: handle}, probe: probeGatewayUDP}
	if _, err := network.Prepare(context.Background(), t.TempDir(), "eth0", "cb123"); err != nil {
		t.Fatal(err)
	}
	for _, operation := range handle.operations {
		if strings.HasPrefix(operation, "link-add cb123") {
			t.Fatalf("compatible TAP recreated: operations=%v", handle.operations)
		}
	}
	if tap.Attrs().MTU != 1450 || tap.Attrs().Flags&net.FlagUp == 0 {
		t.Fatalf("recovered TAP=%+v", tap)
	}
}

func TestNetlinkNetworkDoesNotAdoptCompatibleUnownedTap(t *testing.T) {
	handle := newFakeNetlinkHandle()
	configureFakeDualStack(t, handle)
	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: "cb123", Index: 2}, Mode: netlink.TUNTAP_MODE_TAP,
		Flags: netlink.TUNTAP_MULTI_QUEUE_DEFAULTS | netlink.TUNTAP_VNET_HDR,
	}
	handle.links["cb123"] = tap
	for _, link := range []netlink.Link{handle.links["eth0"], tap} {
		handle.qdiscs[link.Attrs().Index] = []netlink.Qdisc{&netlink.Ingress{QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_INGRESS,
		}}}
		handle.filters[link.Attrs().Index] = []netlink.Filter{&netlink.U32{FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index, Parent: netlink.MakeHandle(0xffff, 0), Priority: tcPriority,
		}}}
	}
	network := &netlinkNetwork{executor: &fakeNetlinkExecutor{handle: handle}, probe: probeGatewayUDP}
	_, err := network.Prepare(context.Background(), t.TempDir(), "eth0", "cb123")
	if err == nil || !strings.Contains(err.Error(), "ownership alias") {
		t.Fatalf("Prepare error=%v", err)
	}
	if err := network.Release(context.Background(), t.TempDir(), "eth0", "cb123"); err == nil || !strings.Contains(err.Error(), "ownership alias") {
		t.Fatalf("Release error=%v", err)
	}
	if handle.links["cb123"] != tap {
		t.Fatal("unowned TAP was deleted")
	}
	for _, index := range []int{1, 2} {
		filters := handle.filters[index]
		if len(filters) != 1 || filters[0].Attrs().Priority != tcPriority {
			t.Fatalf("filters on index %d changed: %+v", index, filters)
		}
	}
}

func TestNetlinkNetworkMutationFailuresRollbackThroughAdapter(t *testing.T) {
	tapName := nameFor("cb", "sandbox-a", 3)
	for _, failOperation := range []string{
		fmt.Sprintf("link-add %s tuntap", tapName),
		fmt.Sprintf("link-alias %s %s", tapName, tapOwnershipAlias(tapName)),
		fmt.Sprintf("link-mtu %s 1450", tapName),
		"link-up " + tapName,
		fmt.Sprintf("addr-list eth0 %d", netlink.FAMILY_ALL),
		fmt.Sprintf("route-list eth0 %d", netlink.FAMILY_V4),
		fmt.Sprintf("neighbor-list 1 %d", netlink.FAMILY_ALL),
		"qdisc-add 1 ingress",
		"qdisc-add 2 ingress",
		fmt.Sprintf("filter-replace 1 %d", tcPriority),
		fmt.Sprintf("filter-replace 2 %d", tcPriority),
	} {
		t.Run(strings.ReplaceAll(failOperation, " ", "_"), func(t *testing.T) {
			handle := newFakeNetlinkHandle()
			configureFakeDualStack(t, handle)
			handle.failOperation = failOperation
			handle.failError = errors.New("injected at " + failOperation)
			if strings.HasPrefix(failOperation, "link-alias ") {
				handle.failCounts = map[string]int{"link-del " + tapName: 1}
			}
			network := &netlinkNetwork{executor: &fakeNetlinkExecutor{handle: handle}, probe: probeGatewayUDP}
			adapterState := filepath.Join(t.TempDir(), "adapter")
			adapter, err := newAdapter(adapterState, testAssets(t), network)
			if err != nil {
				t.Fatal(err)
			}
			request := adapterRequest()
			request.Network.NetnsPath = t.TempDir()
			_, err = adapter.Prepare(context.Background(), request, state.Lease{Generation: 3, LeaseID: "lease-a"})
			if err == nil || !strings.Contains(err.Error(), "injected at "+failOperation) {
				t.Fatalf("Prepare error=%v", err)
			}
			if _, exists := handle.links[tapName]; exists {
				t.Fatalf("TAP remains after rollback: operations=%v", handle.operations)
			}
			if strings.HasPrefix(failOperation, "link-alias ") {
				deleteAttempts := 0
				for _, operation := range handle.operations {
					if operation == "link-del "+tapName {
						deleteAttempts++
					}
				}
				if deleteAttempts != 2 {
					t.Fatalf("unmarked TAP delete attempts=%d operations=%v", deleteAttempts, handle.operations)
				}
			}
			for index, filters := range handle.filters {
				for _, filter := range filters {
					if filter.Attrs().Priority == tcPriority {
						t.Fatalf("reserved filter remains on index %d: %+v", index, filter)
					}
				}
			}
			if _, err := adapter.load("sandbox-a"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("adapter record remains: %v", err)
			}
			entries, err := os.ReadDir(adapter.assets.SharedRootBase)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("shared-root residue=%v", entries)
			}
		})
	}
}

func TestNetlinkNetworkReleaseFailuresRetainAdapterRecordAndRetry(t *testing.T) {
	tapName := nameFor("cb", "sandbox-a", 3)
	for _, failOperation := range []string{
		fmt.Sprintf("filter-del 1 %d", tcPriority),
		fmt.Sprintf("filter-del 2 %d", tcPriority),
		"link-del " + tapName,
	} {
		t.Run(strings.ReplaceAll(failOperation, " ", "_"), func(t *testing.T) {
			handle := newFakeNetlinkHandle()
			configureFakeDualStack(t, handle)
			network := &netlinkNetwork{executor: &fakeNetlinkExecutor{handle: handle}, probe: probeGatewayUDP}
			adapterState := filepath.Join(t.TempDir(), "adapter")
			adapter, err := newAdapter(adapterState, testAssets(t), network)
			if err != nil {
				t.Fatal(err)
			}
			request := adapterRequest()
			request.Network.NetnsPath = t.TempDir()
			lease := state.Lease{Generation: 3, LeaseID: "lease-a"}
			prepared, err := adapter.Prepare(context.Background(), request, lease)
			if err != nil {
				t.Fatal(err)
			}
			handle.filters[1] = append(handle.filters[1], &netlink.U32{FilterAttrs: netlink.FilterAttrs{
				LinkIndex: 1, Parent: netlink.MakeHandle(0xffff, 0), Priority: 7,
			}})
			handle.failOperation = failOperation
			handle.failError = errors.New("injected at " + failOperation)
			release := state.ReleaseRequest{SandboxID: "sandbox-a", Generation: 3, LeaseID: "lease-a"}
			if err := adapter.Release(context.Background(), release, prepared.GetNetwork().GetNetworkHandle()); err == nil || !strings.Contains(err.Error(), "injected at "+failOperation) {
				t.Fatalf("first Release error=%v", err)
			}
			if _, err := adapter.load("sandbox-a"); err != nil {
				t.Fatalf("adapter record not retained: %v", err)
			}
			if err := adapter.Release(context.Background(), release, prepared.GetNetwork().GetNetworkHandle()); err != nil {
				t.Fatalf("Release retry: %v", err)
			}
			if _, err := adapter.load("sandbox-a"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("adapter record remains after retry: %v", err)
			}
			if _, exists := handle.links[tapName]; exists {
				t.Fatal("TAP remains after release retry")
			}
			filters := handle.filters[1]
			if len(filters) != 1 || filters[0].Attrs().Priority != 7 {
				t.Fatalf("unrelated CNI filter changed: %+v", filters)
			}
		})
	}
}

func TestNetlinkNetworkHonorsCanceledContextBeforeMutation(t *testing.T) {
	handle := newFakeNetlinkHandle()
	configureFakeDualStack(t, handle)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	network := &netlinkNetwork{executor: &fakeNetlinkExecutor{handle: handle}, probe: probeGatewayUDP}
	_, err := network.Prepare(ctx, t.TempDir(), "eth0", "cb123")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if len(handle.operations) != 0 {
		t.Fatalf("operations after cancellation=%v", handle.operations)
	}
}
