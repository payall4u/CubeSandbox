//go:build linux

// Copyright (c) 2024 Tencent Inc.
// SPDX-License-Identifier: Apache-2.0

package runtimeresource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	goruntime "runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	runtimev1 "github.com/tencentcloud/CubeSandbox/Cubelet/api/services/runtime/v1"
	"github.com/tencentcloud/CubeSandbox/Cubelet/internal/monotime"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const tcPreference = "49152"

type commandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type nsenterRunner struct{}

func (nsenterRunner) Run(ctx context.Context, netnsPath string, command ...string) (output []byte, err error) {
	started := time.Now()
	trace := monotime.TraceBufferFromContext(ctx)
	identity := startupTraceIdentityFromContext(ctx)
	defer func() {
		if !trace.Enabled() {
			return
		}
		trace.Addf(
			"cube_perf component=cubelet operation=create phase=network-exec sandbox_id=%s pod_uid=%s operation_id=%s netns=%s command=%q ts_mono_us=%d duration_us=%d success=%t",
			identity.sandboxID, identity.podUID, identity.operationID, netnsPath, strings.Join(command, " "), monotime.Micros(), time.Since(started).Microseconds(), err == nil,
		)
	}()
	args := append([]string{"--net=" + netnsPath, "--"}, command...)
	output, err = commandContext(ctx, "nsenter", args...).CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("netns command %q: %w: %s", strings.Join(command, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

var commandContext = newExecCommand

const runtimeResourceVnetHeaderSize = 12

var runtimeResourceIoctlSetPointerInt = unix.IoctlSetPointerInt
var runtimeResourceIoctlSetTunOffload = func(fd int, features uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETOFFLOAD), features)
	if errno != 0 {
		return errno
	}
	return nil
}

// Kept behind a variable to make privileged commands replaceable in unit tests.
var newExecCommand = func(ctx context.Context, name string, args ...string) command {
	return osCommand{ctx: ctx, name: name, args: args}
}

type command interface {
	CombinedOutput() ([]byte, error)
}

type osCommand struct {
	ctx  context.Context
	name string
	args []string
}

func (c osCommand) CombinedOutput() ([]byte, error) {
	return execCombinedOutput(c.ctx, c.name, c.args...)
}

var execCombinedOutput = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return nil, errors.New("exec implementation is not initialized")
}

type linuxNetwork struct{ runner commandRunner }

type commandCNIConfiguration struct {
	mac      string
	mtu      uint32
	ips      []string
	routes   []*runtimev1.Route
	gateways []string
}

func newLinuxNetwork() *linuxNetwork { return &linuxNetwork{runner: nsenterRunner{}} }

func (n *linuxNetwork) Prepare(ctx context.Context, netnsPath, interfaceName, tapName string) (attachment *runtimev1.NetworkAttachment, err error) {
	started := time.Now()
	trace := monotime.TraceBufferFromContext(ctx)
	identity := startupTraceIdentityFromContext(ctx)
	defer func() {
		if !trace.Enabled() {
			return
		}
		trace.Addf(
			"cube_perf component=cubelet operation=create phase=network-prepare backend=command sandbox_id=%s pod_uid=%s operation_id=%s netns=%s interface=%s tap=%s ts_mono_us=%d duration_us=%d success=%t",
			identity.sandboxID, identity.podUID, identity.operationID, netnsPath, interfaceName, tapName, monotime.Micros(), time.Since(started).Microseconds(), err == nil,
		)
	}()
	if _, err := os.Stat(netnsPath); err != nil {
		return nil, err
	}
	waitStarted := time.Now()
	configuration, err := n.waitForCNIConfiguration(ctx, netnsPath, interfaceName)
	if trace.Enabled() {
		trace.Addf(
			"cube_perf component=cubelet operation=create phase=cni-ready-wait backend=command sandbox_id=%s pod_uid=%s operation_id=%s interface=%s ts_mono_us=%d duration_us=%d success=%t",
			identity.sandboxID, identity.podUID, identity.operationID, interfaceName, monotime.Micros(), time.Since(waitStarted).Microseconds(), err == nil,
		)
	}
	if err != nil {
		return nil, err
	}

	if _, err := n.runner.Run(ctx, netnsPath, "ip", "link", "show", "dev", tapName); err != nil {
		if _, createErr := n.runner.Run(ctx, netnsPath, "ip", "tuntap", "add", "dev", tapName, "mode", "tap", "multi_queue", "vnet_hdr"); createErr != nil {
			return nil, createErr
		}
	}
	if _, err := n.runner.Run(ctx, netnsPath, "ip", "link", "set", "dev", tapName, "mtu", strconv.FormatUint(uint64(configuration.mtu), 10), "up"); err != nil {
		return nil, err
	}

	neighbors, err := n.neighbors(ctx, netnsPath, interfaceName, configuration.gateways)
	if err != nil {
		return nil, err
	}
	// Resolve gateway neighbors before redirecting ingress traffic to the TAP.
	// Once the catch-all tc filter is installed, ARP/NDP replies are delivered
	// to the guest instead of the host network stack and cannot populate the
	// namespace neighbor table used to construct the guest attachment.
	interfaceParent, err := n.ensureIngress(ctx, netnsPath, interfaceName)
	if err != nil {
		return nil, err
	}
	tapParent, err := n.ensureIngress(ctx, netnsPath, tapName)
	if err != nil {
		return nil, err
	}
	for _, redirect := range []struct{ source, target, parent string }{
		{interfaceName, tapName, interfaceParent}, {tapName, interfaceName, tapParent},
	} {
		if _, err := n.runner.Run(ctx, netnsPath, "tc", "filter", "replace", "dev", redirect.source, "parent", redirect.parent, "protocol", "all", "pref", tcPreference, "u32", "match", "u8", "0", "0", "action", "mirred", "egress", "redirect", "dev", redirect.target); err != nil {
			return nil, err
		}
	}
	attachment = &runtimev1.NetworkAttachment{
		TapName: tapName, GuestInterfaceName: "eth0", Mac: configuration.mac, Mtu: configuration.mtu,
		Ips: configuration.ips, Routes: configuration.routes, Neighbors: neighbors,
	}
	return attachment, nil
}

func (n *linuxNetwork) waitForCNIConfiguration(ctx context.Context, netnsPath, interfaceName string) (*commandCNIConfiguration, error) {
	deadline := time.Now().Add(cniReadyTimeout)
	var lastPending error
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		linkOutput, err := n.runner.Run(ctx, netnsPath, "ip", "-j", "link", "show", "dev", interfaceName)
		if err != nil {
			if !cniLinkLookupPending(err) {
				return nil, fmt.Errorf("find CNI interface %q: %w", interfaceName, err)
			}
			lastPending = err
		} else {
			var links []struct {
				Address string `json:"address"`
				MTU     uint32 `json:"mtu"`
			}
			if err := json.Unmarshal(linkOutput, &links); err != nil {
				return nil, fmt.Errorf("decode CNI interface: %w", err)
			}
			if len(links) != 1 || links[0].Address == "" || links[0].MTU == 0 {
				return nil, errors.New("CNI interface response must contain one link with MAC and MTU")
			}

			ips, addressErr := n.addresses(ctx, netnsPath, interfaceName)
			if addressErr == nil {
				routes, gateways, routeErr := n.routes(ctx, netnsPath, interfaceName, ips)
				if routeErr == nil {
					return &commandCNIConfiguration{
						mac: links[0].Address, mtu: links[0].MTU, ips: ips, routes: routes, gateways: gateways,
					}, nil
				}
				if !cniConfigurationPending(routeErr) {
					return nil, routeErr
				}
				lastPending = routeErr
			} else {
				if !cniConfigurationPending(addressErr) {
					return nil, addressErr
				}
				lastPending = addressErr
			}
		}

		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("wait for CNI interface %q configuration: %w", interfaceName, lastPending)
		}
		wait := cniReadyPollInterval
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func cniLinkLookupPending(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "does not exist") ||
		strings.Contains(message, "cannot find device")
}

func (n *linuxNetwork) ensureIngress(ctx context.Context, netnsPath, device string) (string, error) {
	output, _ := n.runner.Run(ctx, netnsPath, "tc", "qdisc", "show", "dev", device)
	if strings.Contains(string(output), "clsact ffff:") {
		return "ffff:fff2", nil
	}
	if strings.Contains(string(output), "ingress ffff:") {
		return "ffff:", nil
	}
	_, err := n.runner.Run(ctx, netnsPath, "tc", "qdisc", "add", "dev", device, "ingress")
	return "ffff:", err
}

func (n *linuxNetwork) addresses(ctx context.Context, netnsPath, device string) ([]string, error) {
	output, err := n.runner.Run(ctx, netnsPath, "ip", "-j", "addr", "show", "dev", device)
	if err != nil {
		return nil, err
	}
	var entries []struct {
		Addresses []struct {
			Local     string `json:"local"`
			PrefixLen uint32 `json:"prefixlen"`
			Scope     string `json:"scope"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(output, &entries); err != nil {
		return nil, err
	}
	var result []string
	for _, entry := range entries {
		for _, address := range entry.Addresses {
			if address.Scope == "global" && net.ParseIP(address.Local) != nil {
				result = append(result, fmt.Sprintf("%s/%d", address.Local, address.PrefixLen))
			}
		}
	}
	if len(result) == 0 {
		return nil, errors.New("CNI interface has no global IP address")
	}
	return result, nil
}

func addressFamily(value string) int {
	ip := net.ParseIP(strings.SplitN(value, "/", 2)[0])
	if ip == nil {
		return 0
	}
	if ip.To4() != nil {
		return 4
	}
	return 6
}

func (n *linuxNetwork) routes(ctx context.Context, netnsPath, device string, ips []string) ([]*runtimev1.Route, []string, error) {
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
		output, err := n.runner.Run(ctx, netnsPath, "ip", "-j", "-"+strconv.Itoa(family), "route", "show")
		if err != nil {
			return nil, nil, err
		}
		var entries []struct {
			Dst     string `json:"dst"`
			Gateway string `json:"gateway"`
			Dev     string `json:"dev"`
			PrefSrc string `json:"prefsrc"`
			Scope   string `json:"scope"`
		}
		if err := json.Unmarshal(output, &entries); err != nil {
			return nil, nil, err
		}
		var familyRoutes []*runtimev1.Route
		var gateway string
		for _, entry := range entries {
			if entry.Dev != device {
				continue
			}
			destination := entry.Dst
			if destination == "" || destination == "default" {
				if family == 4 {
					destination = "0.0.0.0/0"
				} else {
					destination = "::/0"
				}
			}
			if entry.PrefSrc == "" {
				entry.PrefSrc = source
			}
			if entry.Gateway != "" && gateway == "" {
				gateway = entry.Gateway
			}
			familyRoutes = append(familyRoutes, &runtimev1.Route{Destination: destination, Gateway: entry.Gateway, Source: entry.PrefSrc, Device: "eth0", Scope: routeScope(entry.Scope)})
		}
		if gateway == "" {
			return nil, nil, fmt.Errorf("CNI interface has no IPv%d default gateway", family)
		}
		prefix := "/32"
		if family == 6 {
			prefix = "/128"
		}
		if !hasGatewayHostRoute(familyRoutes, gateway) {
			result = append(result, &runtimev1.Route{Destination: gateway + prefix, Source: source, Device: "eth0", Scope: 253})
		}
		result = append(result, familyRoutes...)
		gateways = append(gateways, gateway)
	}
	if len(gateways) == 0 {
		return nil, nil, errors.New("CNI interface has no default gateway")
	}
	return result, gateways, nil
}

func hasGatewayHostRoute(routes []*runtimev1.Route, gateway string) bool {
	gatewayIP := net.ParseIP(gateway)
	if gatewayIP == nil {
		return false
	}
	wantBits := 128
	if gatewayIP.To4() != nil {
		wantBits = 32
	}
	for _, route := range routes {
		if route.GetGateway() != "" || route.GetDevice() != "eth0" {
			continue
		}
		destination := route.GetDestination()
		if !strings.Contains(destination, "/") {
			if destinationIP := net.ParseIP(destination); destinationIP != nil && destinationIP.Equal(gatewayIP) {
				return true
			}
			continue
		}
		destinationIP, network, err := net.ParseCIDR(destination)
		if err != nil {
			continue
		}
		ones, bits := network.Mask.Size()
		if bits == wantBits && ones == wantBits && destinationIP.Equal(gatewayIP) {
			return true
		}
	}
	return false
}

func (n *linuxNetwork) neighbors(ctx context.Context, netnsPath, device string, gateways []string) ([]*runtimev1.Neighbor, error) {
	for attempt := 0; attempt < 3; attempt++ {
		output, err := n.runner.Run(ctx, netnsPath, "ip", "-j", "neigh", "show", "dev", device)
		if err != nil {
			return nil, err
		}
		var entries []struct {
			Dst    string `json:"dst"`
			LLAddr string `json:"lladdr"`
			Dev    string `json:"dev"`
		}
		if err := json.Unmarshal(output, &entries); err != nil {
			return nil, err
		}
		byIP := make(map[string]string, len(entries))
		for _, entry := range entries {
			if entry.LLAddr != "" {
				byIP[entry.Dst] = entry.LLAddr
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
		for _, gateway := range gateways {
			if byIP[gateway] != "" {
				continue
			}
			args := []string{"ping"}
			if addressFamily(gateway) == 6 {
				args = append(args, "-6")
			}
			args = append(args, "-c", "1", "-W", "1", gateway)
			_, _ = n.runner.Run(ctx, netnsPath, args...)
		}
	}
	return nil, errors.New("CNI default gateway has no neighbor MAC")
}

func (n *linuxNetwork) Release(ctx context.Context, netnsPath, interfaceName, tapName string) error {
	if _, err := os.Stat(netnsPath); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	for _, device := range []string{interfaceName, tapName} {
		parent := "ffff:"
		if output, _ := n.runner.Run(ctx, netnsPath, "tc", "qdisc", "show", "dev", device); strings.Contains(string(output), "clsact ffff:") {
			parent = "ffff:fff2"
		}
		_, _ = n.runner.Run(ctx, netnsPath, "tc", "filter", "del", "dev", device, "parent", parent, "pref", tcPreference)
	}
	_, err := n.runner.Run(ctx, netnsPath, "ip", "tuntap", "del", "dev", tapName, "mode", "tap", "multi_queue")
	if err != nil && !strings.Contains(err.Error(), "Cannot find device") {
		return err
	}
	return nil
}

type tapOpenResult struct {
	file *os.File
	err  error
}

func (n *linuxNetwork) Open(netnsPath, tapName string) (*os.File, error) {
	return openTapInNetworkNamespace(netnsPath, tapName)
}

func openTapInNetworkNamespace(netnsPath, tapName string) (*os.File, error) {
	result := make(chan tapOpenResult, 1)
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
			result <- tapOpenResult{err: err}
			return
		}
		defer original.Close()
		target, err := netns.GetFromPath(netnsPath)
		if err != nil {
			result <- tapOpenResult{err: err}
			return
		}
		defer target.Close()
		if err := netns.Set(target); err != nil {
			result <- tapOpenResult{err: err}
			return
		}

		file, openErr := openTap(tapName)
		restoreErr := netns.Set(original)
		if restoreErr != nil {
			if file != nil {
				_ = file.Close()
			}
			// Returning from a goroutine still locked to an OS thread makes the
			// Go runtime terminate that thread instead of reusing it in the target netns.
			terminateThread = true
			result <- tapOpenResult{err: fmt.Errorf("restore network namespace: %w", restoreErr)}
			return
		}
		result <- tapOpenResult{file: file, err: openErr}
	}()
	opened := <-result
	return opened.file, opened.err
}

func openTap(tapName string) (*os.File, error) {
	request, err := unix.NewIfreq(tapName)
	if err != nil {
		return nil, err
	}
	request.SetUint16(uint16(unix.IFF_TAP | unix.IFF_NO_PI | unix.IFF_VNET_HDR | unix.IFF_MULTI_QUEUE))
	fd, err := unix.Open("/dev/net/tun", os.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := prepareTapForHandoff(fd); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "/dev/net/tun"), nil
}

// prepareTapForHandoff must run while the TAP's owning netns is current.
// The VMM uses virtio_net_hdr_v1 (12 bytes), while Linux defaults a newly
// opened IFF_VNET_HDR queue to the legacy 10-byte header. A mismatch leaks the
// final two header bytes into the Ethernet frame and makes CNI datapaths reject
// otherwise valid IPv4/IPv6 traffic. Offloads stay disabled because the fd is
// handed to a VMM outside the TAP netns and the tcfilter path expects complete
// packets, matching CubeShim's existing S0 cross-netns contract.
func prepareTapForHandoff(fd int) error {
	if err := runtimeResourceIoctlSetPointerInt(fd, unix.TUNSETVNETHDRSZ, runtimeResourceVnetHeaderSize); err != nil {
		return fmt.Errorf("set RuntimeResource TAP vnet header size: %w", err)
	}
	if err := runtimeResourceIoctlSetTunOffload(fd, 0); err != nil {
		return fmt.Errorf("disable RuntimeResource TAP offloads: %w", err)
	}
	return nil
}

func routeScope(scope string) uint32 {
	switch scope {
	case "host":
		return 254
	case "link":
		return 253
	default:
		return 0
	}
}
