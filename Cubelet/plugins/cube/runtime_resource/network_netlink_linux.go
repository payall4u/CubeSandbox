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
	goruntime "runtime"
	"strings"
	"time"

	runtimev1 "github.com/tencentcloud/CubeSandbox/Cubelet/api/services/runtime/v1"
	"github.com/tencentcloud/CubeSandbox/Cubelet/internal/monotime"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	networkBackendEnvironment = "CUBE_RUNTIME_RESOURCE_NETWORK_BACKEND"
	netlinkBackend            = "netlink"
	commandBackend            = "command"
	tcPriority                = uint16(49152)
	dumpRetryLimit            = 4
	cniReadyTimeout           = 2 * time.Second
	cniReadyPollInterval      = 2 * time.Millisecond
	tapDeleteRetryLimit       = 3
	tapDeleteRetryInterval    = time.Millisecond
	// Cilium can publish the gateway neighbor asynchronously after CNI ADD.
	// Keep this below the broader CNI readiness deadline, but long enough to
	// absorb scheduler/load jitter; failing RunPodSandbox makes kubelet wait
	// roughly ten seconds before retrying the entire sandbox creation.
	neighborResolutionTimeout = 250 * time.Millisecond
	neighborPollInterval      = 2 * time.Millisecond
	neighborProbeInterval     = 5 * time.Millisecond
	tapOwnershipAliasPrefix   = "cubesandbox-runtime-resource:"
)

type netlinkHandle interface {
	LinkByName(string) (netlink.Link, error)
	LinkAdd(netlink.Link) error
	LinkDel(netlink.Link) error
	LinkSetMTU(netlink.Link, int) error
	LinkSetUp(netlink.Link) error
	LinkSetAlias(netlink.Link, string) error
	AddrList(netlink.Link, int) ([]netlink.Addr, error)
	RouteList(netlink.Link, int) ([]netlink.Route, error)
	NeighList(int, int) ([]netlink.Neigh, error)
	QdiscList(netlink.Link) ([]netlink.Qdisc, error)
	QdiscAdd(netlink.Qdisc) error
	FilterList(netlink.Link, uint32) ([]netlink.Filter, error)
	FilterReplace(netlink.Filter) error
	FilterDel(netlink.Filter) error
}

type netlinkNamespaceExecutor interface {
	Run(context.Context, string, func(netlinkHandle) error) error
}

type threadNetlinkNamespaceExecutor struct{}

type namespaceExecutionResult struct{ err error }

func (threadNetlinkNamespaceExecutor) Run(ctx context.Context, netnsPath string, operation func(netlinkHandle) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	result := make(chan namespaceExecutionResult, 1)
	go func() {
		goruntime.LockOSThread()
		terminateThread := false
		defer func() {
			if !terminateThread {
				goruntime.UnlockOSThread()
			}
		}()

		original, err := netns.Get()
		if err != nil {
			result <- namespaceExecutionResult{err: fmt.Errorf("get current network namespace: %w", err)}
			return
		}
		defer original.Close()
		target, err := netns.GetFromPath(netnsPath)
		if err != nil {
			result <- namespaceExecutionResult{err: fmt.Errorf("open network namespace %q: %w", netnsPath, err)}
			return
		}
		defer target.Close()
		if err := netns.Set(target); err != nil {
			result <- namespaceExecutionResult{err: fmt.Errorf("enter network namespace %q: %w", netnsPath, err)}
			return
		}

		// All operations in this backend use rtnetlink. Avoid opening unused
		// sockets for the other netlink families on every Pod startup.
		handle, operationErr := netlink.NewHandle(unix.NETLINK_ROUTE)
		if operationErr == nil {
			operationErr = operation(handle)
			handle.Close()
		}
		restoreErr := netns.Set(original)
		if restoreErr != nil {
			// A goroutine that returns while still locked makes the Go runtime
			// discard this OS thread instead of reusing it in the Pod netns.
			terminateThread = true
			result <- namespaceExecutionResult{err: fmt.Errorf("restore network namespace: %w", restoreErr)}
			return
		}
		result <- namespaceExecutionResult{err: operationErr}
	}()
	return (<-result).err
}

type gatewayProbe func(context.Context, string, net.IP) error

type netlinkNetwork struct {
	executor netlinkNamespaceExecutor
	probe    gatewayProbe
}

func newNodeNetwork() (NetworkOps, error) {
	switch backend := strings.ToLower(strings.TrimSpace(os.Getenv(networkBackendEnvironment))); backend {
	case "", netlinkBackend:
		return newNetlinkNetwork(), nil
	case commandBackend:
		return newLinuxNetwork(), nil
	default:
		return nil, fmt.Errorf("unsupported %s=%q (want %q or %q)", networkBackendEnvironment, backend, netlinkBackend, commandBackend)
	}
}

func newNetlinkNetwork() *netlinkNetwork {
	return &netlinkNetwork{executor: threadNetlinkNamespaceExecutor{}, probe: probeGatewayUDP}
}

func (n *netlinkNetwork) Prepare(ctx context.Context, netnsPath, interfaceName, tapName string) (attachment *runtimev1.NetworkAttachment, err error) {
	started := time.Now()
	trace := monotime.TraceBufferFromContext(ctx)
	identity := startupTraceIdentityFromContext(ctx)
	defer func() {
		if !trace.Enabled() {
			return
		}
		trace.Addf(
			"cube_perf component=cubelet operation=create phase=network-prepare backend=netlink sandbox_id=%s pod_uid=%s operation_id=%s netns=%s interface=%s tap=%s ts_mono_us=%d duration_us=%d success=%t",
			identity.sandboxID, identity.podUID, identity.operationID, netnsPath, interfaceName, tapName, monotime.Micros(), time.Since(started).Microseconds(), err == nil,
		)
	}()
	if _, err := os.Stat(netnsPath); err != nil {
		return nil, err
	}
	err = n.executor.Run(ctx, netnsPath, func(handle netlinkHandle) error {
		var prepareErr error
		attachment, prepareErr = n.prepare(ctx, handle, interfaceName, tapName)
		return prepareErr
	})
	if err != nil {
		return nil, err
	}
	return attachment, nil
}

func (n *netlinkNetwork) prepare(ctx context.Context, handle netlinkHandle, interfaceName, tapName string) (*runtimev1.NetworkAttachment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	waitStarted := time.Now()
	cniLink, ips, routes, gateways, err := waitForCNIConfiguration(ctx, handle, interfaceName)
	trace := monotime.TraceBufferFromContext(ctx)
	identity := startupTraceIdentityFromContext(ctx)
	if trace.Enabled() {
		trace.Addf(
			"cube_perf component=cubelet operation=create phase=cni-ready-wait backend=netlink sandbox_id=%s pod_uid=%s operation_id=%s interface=%s ts_mono_us=%d duration_us=%d success=%t",
			identity.sandboxID, identity.podUID, identity.operationID, interfaceName, monotime.Micros(), time.Since(waitStarted).Microseconds(), err == nil,
		)
	}
	if err != nil {
		return nil, err
	}
	mac := cniLink.Attrs().HardwareAddr.String()
	mtu := cniLink.Attrs().MTU
	tap, err := ensureNetlinkTap(ctx, handle, tapName)
	if err != nil {
		return nil, err
	}
	if err := handle.LinkSetMTU(tap, mtu); err != nil {
		return nil, fmt.Errorf("set TAP %q MTU: %w", tapName, err)
	}
	if err := handle.LinkSetUp(tap); err != nil {
		return nil, fmt.Errorf("set TAP %q up: %w", tapName, err)
	}
	neighbors, err := n.netlinkNeighbors(ctx, handle, cniLink, interfaceName, gateways)
	if err != nil {
		return nil, err
	}
	// Resolve gateway neighbors before redirecting ingress traffic to the TAP.
	// Once installed, the catch-all filter sends ARP/NDP replies to the guest.
	cniIngressParent, err := ensureNetlinkIngress(ctx, handle, cniLink)
	if err != nil {
		return nil, err
	}
	tapIngressParent, err := ensureNetlinkIngress(ctx, handle, tap)
	if err != nil {
		return nil, err
	}
	if err := replaceNetlinkRedirect(ctx, handle, cniLink, tap, cniIngressParent); err != nil {
		return nil, err
	}
	if err := replaceNetlinkRedirect(ctx, handle, tap, cniLink, tapIngressParent); err != nil {
		return nil, err
	}
	return &runtimev1.NetworkAttachment{
		TapName: tapName, GuestInterfaceName: "eth0", Mac: mac, Mtu: uint32(mtu),
		Ips: ips, Routes: routes, Neighbors: neighbors,
	}, nil
}

func waitForCNIConfiguration(ctx context.Context, handle netlinkHandle, interfaceName string) (netlink.Link, []string, []*runtimev1.Route, []string, error) {
	deadline := time.Now().Add(cniReadyTimeout)
	var lastPending error
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, nil, nil, err
		}
		link, err := handle.LinkByName(interfaceName)
		switch {
		case isLinkNotFound(err):
			lastPending = fmt.Errorf("find CNI interface %q: %w", interfaceName, err)
		case err != nil:
			return nil, nil, nil, nil, fmt.Errorf("find CNI interface %q: %w", interfaceName, err)
		case link.Attrs().HardwareAddr.String() == "" || link.Attrs().MTU <= 0:
			lastPending = errors.New("CNI interface must contain a MAC address and positive MTU")
		default:
			ips, addressErr := netlinkAddresses(ctx, handle, link)
			if addressErr == nil {
				routes, gateways, routeErr := netlinkRoutes(ctx, handle, link, ips)
				if routeErr == nil {
					return link, ips, routes, gateways, nil
				}
				if !cniConfigurationPending(routeErr) {
					return nil, nil, nil, nil, routeErr
				}
				lastPending = routeErr
			} else {
				if !cniConfigurationPending(addressErr) {
					return nil, nil, nil, nil, addressErr
				}
				lastPending = addressErr
			}
		}

		if !time.Now().Before(deadline) {
			return nil, nil, nil, nil, fmt.Errorf("wait for CNI interface %q configuration: %w", interfaceName, lastPending)
		}
		wait := cniReadyPollInterval
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
		select {
		case <-ctx.Done():
			return nil, nil, nil, nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

func cniConfigurationPending(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return message == "CNI interface has no global IP address" ||
		strings.Contains(message, "CNI interface has no IPv4 default gateway") ||
		strings.Contains(message, "CNI interface has no IPv6 default gateway") ||
		message == "CNI interface has no default gateway"
}

func ensureNetlinkTap(ctx context.Context, handle netlinkHandle, tapName string) (netlink.Link, error) {
	tap, err := handle.LinkByName(tapName)
	if err == nil {
		if err := validateNetlinkTap(tap, tapName); err != nil {
			return nil, err
		}
		return tap, nil
	}
	if !isLinkNotFound(err) {
		return nil, fmt.Errorf("find TAP %q: %w", tapName, err)
	}
	created := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: tapName},
		Mode:      netlink.TUNTAP_MODE_TAP,
		Flags:     netlink.TUNTAP_MULTI_QUEUE_DEFAULTS | netlink.TUNTAP_VNET_HDR,
		Queues:    1,
	}
	if err := handle.LinkAdd(created); err != nil {
		return nil, fmt.Errorf("create TAP %q: %w", tapName, err)
	}
	for _, file := range created.Fds {
		_ = file.Close()
	}
	created.Fds = nil
	alias := tapOwnershipAlias(tapName)
	if err := handle.LinkSetAlias(created, alias); err != nil {
		// This invocation created the device, so it is safe to delete even
		// before the durable ownership marker is installed.
		if cleanupErr := deleteKnownCreatedTap(handle, created); cleanupErr != nil {
			return nil, fmt.Errorf("mark TAP %q ownership: %w; delete unmarked TAP: %v", tapName, err, cleanupErr)
		}
		return nil, fmt.Errorf("mark TAP %q ownership: %w", tapName, err)
	}
	created.Attrs().Alias = alias
	return created, nil
}

func deleteKnownCreatedTap(handle netlinkHandle, tap netlink.Link) error {
	var lastErr error
	for attempt := 0; attempt < tapDeleteRetryLimit; attempt++ {
		lastErr = handle.LinkDel(tap)
		if lastErr == nil || isLinkNotFound(lastErr) {
			return nil
		}
		if attempt+1 < tapDeleteRetryLimit {
			time.Sleep(tapDeleteRetryInterval)
		}
	}
	return lastErr
}

func tapOwnershipAlias(tapName string) string {
	return tapOwnershipAliasPrefix + tapName
}

func validateNetlinkTap(link netlink.Link, tapName string) error {
	tap, ok := link.(*netlink.Tuntap)
	if !ok {
		return fmt.Errorf("existing link %q has type %q, want tuntap", tapName, link.Type())
	}
	if tap.Mode != netlink.TUNTAP_MODE_TAP {
		return fmt.Errorf("existing tuntap %q has mode %q, want tap", tapName, tap.Mode)
	}
	required := netlink.TUNTAP_MULTI_QUEUE | netlink.TUNTAP_VNET_HDR | netlink.TUNTAP_NO_PI
	if tap.Flags&required != required {
		return fmt.Errorf("existing TAP %q flags=%#x lack required multi_queue/vnet_hdr/no_pi flags %#x", tapName, tap.Flags, required)
	}
	if tap.NonPersist {
		return fmt.Errorf("existing TAP %q is non-persistent", tapName)
	}
	if tap.Attrs().Alias != tapOwnershipAlias(tapName) {
		return fmt.Errorf("existing TAP %q ownership alias=%q, want %q", tapName, tap.Attrs().Alias, tapOwnershipAlias(tapName))
	}
	return nil
}

func isLinkNotFound(err error) bool {
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT)
}

func netlinkAddresses(ctx context.Context, handle netlinkHandle, link netlink.Link) ([]string, error) {
	addresses, err := dumpWithRetry(ctx, func() ([]netlink.Addr, error) {
		return handle.AddrList(link, netlink.FAMILY_ALL)
	})
	if err != nil {
		return nil, fmt.Errorf("list addresses for %q: %w", link.Attrs().Name, err)
	}
	result := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if address.Scope != unix.RT_SCOPE_UNIVERSE || address.IPNet == nil || address.IP == nil {
			continue
		}
		ones, bits := address.Mask.Size()
		if ones < 0 || (bits != 32 && bits != 128) {
			continue
		}
		result = append(result, fmt.Sprintf("%s/%d", address.IP.String(), ones))
	}
	if len(result) == 0 {
		return nil, errors.New("CNI interface has no global IP address")
	}
	return result, nil
}

func netlinkRoutes(ctx context.Context, handle netlinkHandle, link netlink.Link, ips []string) ([]*runtimev1.Route, []string, error) {
	sources := make(map[int]string)
	for _, value := range ips {
		family := addressFamily(value)
		if family != 0 {
			if _, exists := sources[family]; !exists {
				sources[family] = strings.SplitN(value, "/", 2)[0]
			}
		}
	}
	var result []*runtimev1.Route
	var gateways []string
	for _, family := range []int{4, 6} {
		source, present := sources[family]
		if !present {
			continue
		}
		nlFamily := netlink.FAMILY_V4
		defaultDestination := "0.0.0.0/0"
		hostPrefix := "/32"
		if family == 6 {
			nlFamily = netlink.FAMILY_V6
			defaultDestination = "::/0"
			hostPrefix = "/128"
		}
		entries, err := dumpWithRetry(ctx, func() ([]netlink.Route, error) {
			return handle.RouteList(link, nlFamily)
		})
		if err != nil {
			return nil, nil, fmt.Errorf("list IPv%d routes for %q: %w", family, link.Attrs().Name, err)
		}
		var familyRoutes []*runtimev1.Route
		var gateway, fallbackGateway string
		for _, entry := range entries {
			if entry.LinkIndex != 0 && entry.LinkIndex != link.Attrs().Index {
				continue
			}
			if entry.Table != 0 && entry.Table != unix.RT_TABLE_MAIN {
				continue
			}
			destination := defaultDestination
			if entry.Dst != nil {
				destination = entry.Dst.String()
			}
			entrySource := source
			if entry.Src != nil && !entry.Src.IsUnspecified() {
				entrySource = entry.Src.String()
			}
			entryGateway := ""
			if entry.Gw != nil && !entry.Gw.IsUnspecified() {
				entryGateway = entry.Gw.String()
				if fallbackGateway == "" {
					fallbackGateway = entryGateway
				}
				if entry.Dst == nil && gateway == "" {
					gateway = entryGateway
				}
			}
			familyRoutes = append(familyRoutes, &runtimev1.Route{
				Destination: destination, Gateway: entryGateway, Source: entrySource,
				Device: "eth0", Scope: uint32(entry.Scope),
			})
		}
		if gateway == "" {
			gateway = fallbackGateway
		}
		if gateway == "" {
			return nil, nil, fmt.Errorf("CNI interface has no IPv%d default gateway", family)
		}
		if !hasGatewayHostRoute(familyRoutes, gateway) {
			result = append(result, &runtimev1.Route{Destination: gateway + hostPrefix, Source: source, Device: "eth0", Scope: unix.RT_SCOPE_LINK})
		}
		result = append(result, familyRoutes...)
		gateways = append(gateways, gateway)
	}
	if len(gateways) == 0 {
		return nil, nil, errors.New("CNI interface has no default gateway")
	}
	return result, gateways, nil
}

func (n *netlinkNetwork) netlinkNeighbors(ctx context.Context, handle netlinkHandle, link netlink.Link, device string, gateways []string) ([]*runtimev1.Neighbor, error) {
	deadline := time.Now().Add(neighborResolutionTimeout)
	nextProbe := time.Time{}
	for {
		entries, err := dumpWithRetry(ctx, func() ([]netlink.Neigh, error) {
			return handle.NeighList(link.Attrs().Index, netlink.FAMILY_ALL)
		})
		if err != nil {
			return nil, fmt.Errorf("list neighbors for %q: %w", device, err)
		}
		byIP := make(map[string]string, len(entries))
		for _, entry := range entries {
			if entry.IP != nil && len(entry.HardwareAddr) != 0 && entry.State&netlink.NUD_FAILED == 0 {
				byIP[entry.IP.String()] = entry.HardwareAddr.String()
			}
		}
		neighbors := make([]*runtimev1.Neighbor, 0, len(gateways))
		for _, gateway := range gateways {
			if mac := byIP[gateway]; mac != "" {
				neighbors = append(neighbors, &runtimev1.Neighbor{Ip: gateway, Mac: mac, Device: "eth0"})
			}
		}
		if len(neighbors) == len(gateways) {
			return neighbors, nil
		}
		now := time.Now()
		if !now.Before(deadline) {
			return nil, errors.New("CNI default gateway has no neighbor MAC")
		}
		if nextProbe.IsZero() || !now.Before(nextProbe) {
			for _, gateway := range gateways {
				if byIP[gateway] == "" {
					_ = n.probe(ctx, device, net.ParseIP(gateway))
				}
			}
			nextProbe = now.Add(neighborProbeInterval)
		}
		wait := neighborPollInterval
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
}

func probeGatewayUDP(ctx context.Context, device string, gateway net.IP) error {
	if gateway == nil {
		return errors.New("gateway IP is invalid")
	}
	network := "udp4"
	zone := ""
	if gateway.To4() == nil {
		network = "udp6"
		if gateway.IsLinkLocalUnicast() {
			zone = device
		}
	}
	dialer := net.Dialer{Timeout: 20 * time.Millisecond}
	connection, err := dialer.DialContext(ctx, network, (&net.UDPAddr{IP: gateway, Port: 9, Zone: zone}).String())
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	_, err = connection.Write([]byte{0})
	return err
}

func ensureNetlinkIngress(ctx context.Context, handle netlinkHandle, link netlink.Link) (uint32, error) {
	qdiscs, err := dumpWithRetry(ctx, func() ([]netlink.Qdisc, error) {
		return handle.QdiscList(link)
	})
	if err != nil {
		return 0, fmt.Errorf("list qdiscs for %q: %w", link.Attrs().Name, err)
	}
	if parent, exists := netlinkIngressParent(qdiscs); exists {
		return parent, nil
	}
	qdisc := &netlink.Ingress{QdiscAttrs: netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_INGRESS,
	}}
	if err := handle.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return 0, fmt.Errorf("add ingress qdisc to %q: %w", link.Attrs().Name, err)
	}
	return netlink.MakeHandle(0xffff, 0), nil
}

func netlinkIngressParent(qdiscs []netlink.Qdisc) (uint32, bool) {
	// clsact and ingress are mutually exclusive in a valid kernel state. Prefer
	// clsact if a partial/foreign dump contains both, because its ingress hook
	// has the more specific ffff:fff2 parent.
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			return netlink.HANDLE_MIN_INGRESS, true
		}
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "ingress" {
			return netlink.MakeHandle(0xffff, 0), true
		}
	}
	return 0, false
}

func replaceNetlinkRedirect(ctx context.Context, handle netlinkHandle, source, target netlink.Link, parent uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	filter := &netlink.U32{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: source.Attrs().Index, Parent: parent,
			Priority: tcPriority, Protocol: unix.ETH_P_ALL,
		},
		Actions: []netlink.Action{netlink.NewMirredAction(target.Attrs().Index)},
	}
	if err := handle.FilterReplace(filter); err != nil {
		return fmt.Errorf("redirect ingress from %q to %q: %w", source.Attrs().Name, target.Attrs().Name, err)
	}
	return nil
}

func (n *netlinkNetwork) Release(ctx context.Context, netnsPath, interfaceName, tapName string) error {
	if _, err := os.Stat(netnsPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return n.executor.Run(ctx, netnsPath, func(handle netlinkHandle) error {
		tap, tapErr := handle.LinkByName(tapName)
		if tapErr == nil {
			// Validate ownership and ABI before touching either the CNI link or
			// the colliding device. Prepare failures call Release, so a foreign
			// same-name link must make the entire cleanup path fail closed.
			if err := validateNetlinkTap(tap, tapName); err != nil {
				return fmt.Errorf("refuse TAP release: %w", err)
			}
		} else if !isLinkNotFound(tapErr) {
			return fmt.Errorf("find TAP %q during release: %w", tapName, tapErr)
		}
		for _, name := range []string{interfaceName, tapName} {
			link, err := handle.LinkByName(name)
			if isLinkNotFound(err) {
				continue
			}
			if err != nil {
				return fmt.Errorf("find link %q during release: %w", name, err)
			}
			qdiscs, err := dumpWithRetry(ctx, func() ([]netlink.Qdisc, error) {
				return handle.QdiscList(link)
			})
			if err != nil {
				return fmt.Errorf("list qdiscs for %q during release: %w", name, err)
			}
			parent, exists := netlinkIngressParent(qdiscs)
			if !exists {
				continue
			}
			filters, err := dumpWithRetry(ctx, func() ([]netlink.Filter, error) {
				return handle.FilterList(link, parent)
			})
			if err != nil {
				return fmt.Errorf("list filters for %q parent %#x during release: %w", name, parent, err)
			}
			for _, filter := range filters {
				if filter.Attrs().Priority == tcPriority {
					if err := handle.FilterDel(filter); err != nil && !isLinkNotFound(err) {
						return fmt.Errorf("delete reserved filter from %q: %w", name, err)
					}
				}
			}
		}
		if isLinkNotFound(tapErr) {
			return nil
		}
		if err := handle.LinkDel(tap); err != nil && !isLinkNotFound(err) {
			return fmt.Errorf("delete TAP %q: %w", tapName, err)
		}
		return nil
	})
}

func (n *netlinkNetwork) Open(netnsPath, tapName string) (*os.File, error) {
	return openTapInNetworkNamespace(netnsPath, tapName)
}

func dumpWithRetry[T any](ctx context.Context, operation func() ([]T, error)) ([]T, error) {
	for attempt := 0; attempt < dumpRetryLimit; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := operation()
		if err == nil {
			return result, nil
		}
		if !errors.Is(err, netlink.ErrDumpInterrupted) && !errors.Is(err, unix.EINTR) {
			return nil, err
		}
	}
	return nil, netlink.ErrDumpInterrupted
}
