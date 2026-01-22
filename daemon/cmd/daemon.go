// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	cnicell "github.com/cilium/cilium/daemon/cmd/cni"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	linuxdatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/datapath/linux/ipsec"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	policyAPI "github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

const (
	// AutoCIDR indicates that a CIDR should be allocated
	AutoCIDR = "auto"
)

// Daemon is the cilium daemon that is in charge of perform all necessary plumbing,
// monitoring when a LXC starts.
type Daemon struct {
	ctx             context.Context
	logger          *slog.Logger
	metricsRegistry *metrics.Registry
	clientset       k8sClient.Clientset
	db              *statedb.DB
	policy          policy.PolicyRepository
	idmgr           identitymanager.IDManager

	monitorAgent monitoragent.Agent

	directRoutingDev datapathTables.DirectRoutingDevice
	routes           statedb.Table[*datapathTables.Route]
	devices          statedb.Table[*datapathTables.Device]
	nodeAddrs        statedb.Table[datapathTables.NodeAddress]

	clustermesh *clustermesh.ClusterMesh

	mtuConfig mtu.MTU

	nodeAddressing datapath.NodeAddressing

	// nodeDiscovery defines the node discovery logic of the agent
	nodeDiscovery  *nodediscovery.NodeDiscovery
	nodeLocalStore *node.LocalNodeStore

	// ipam is the IP address manager of the agent
	ipam *ipam.IPAM

	endpointCreator endpointcreator.EndpointCreator
	endpointManager endpointmanager.EndpointManager

	endpointRestoreComplete       chan struct{}
	endpointInitialPolicyComplete chan struct{}

	identityAllocator identitycell.CachingIdentityAllocator
	identityRestorer  *identityrestoration.LocalIdentityRestorer
	ipcache           *ipcache.IPCache

	k8sWatcher *watchers.K8sWatcher

	endpointMetadata endpointmetadata.EndpointMetadataFetcher

	// healthEndpointRouting is the information required to set up the health
	// endpoint's routing in ENI or Azure IPAM mode
	healthEndpointRouting *linuxrouting.RoutingInfo

	ciliumHealth health.CiliumHealthManager

	// Controllers owned by the daemon
	controllers *controller.Manager
	jobGroup    job.Group

	bwManager datapath.BandwidthManager

	maglevConfig maglev.Config

	lbConfig loadbalancer.Config
	kprCfg   kpr.KPRConfig

	cniConfigManager cnicell.CNIConfigManager
}

func (d *Daemon) init() error {
	if !option.Config.DryMode {
		if option.Config.EnableL7Proxy {
			if err := linuxdatapath.NodeEnsureLocalRoutingRule(); err != nil {
				return fmt.Errorf("ensuring local routing rule: %w", err)
			}
		}
	}
	return nil
}

// removeOldRouterState will try to ensure that the only IP assigned to the
// `cilium_host` interface is the given restored IP. If the given IP is nil,
// then it attempts to clear all IPs from the interface.
func removeOldRouterState(logger *slog.Logger, ipv6 bool, restoredIP net.IP) error {
	l, err := safenetlink.LinkByName(defaults.HostDevice)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		// There's no old state remove as the host device doesn't exist.
		// This is always the case when the agent is started for the first time.
		return nil
	}
	if err != nil {
		return resiliency.Retryable(err)
	}

	family := netlink.FAMILY_V4
	if ipv6 {
		family = netlink.FAMILY_V6
	}
	addrs, err := safenetlink.AddrList(l, family)
	if err != nil {
		return resiliency.Retryable(err)
	}

	isRestoredIP := func(a netlink.Addr) bool {
		return restoredIP != nil && restoredIP.Equal(a.IP)
	}
	if len(addrs) == 0 || (len(addrs) == 1 && isRestoredIP(addrs[0])) {
		return nil // nothing to clean up
	}

	logger.Info("More than one stale router IP was found on the cilium_host device after restoration, cleaning up old router IPs.")

	for _, a := range addrs {
		if isRestoredIP(a) {
			continue
		}
		logger.Debug(
			"Removing stale router IP from cilium_host device",
			logfields.IPAddr, a.IP,
		)
		if e := netlink.AddrDel(l, &a); e != nil {
			err = errors.Join(err, resiliency.Retryable(fmt.Errorf("failed to remove IP %s: %w", a.IP, e)))
		}
	}

	return err
}

// removeOldCiliumHostIPs calls removeOldRouterState() for both IPv4 and IPv6
// in a retry loop.
func (d *Daemon) removeOldCiliumHostIPs(ctx context.Context, restoredRouterIPv4, restoredRouterIPv6 net.IP) {
	gcHostIPsFn := func(ctx context.Context, retries int) (done bool, err error) {
		var errs error
		if option.Config.EnableIPv4 {
			errs = errors.Join(errs, removeOldRouterState(d.logger, false, restoredRouterIPv4))
		}
		if option.Config.EnableIPv6 {
			errs = errors.Join(errs, removeOldRouterState(d.logger, true, restoredRouterIPv6))
		}
		if resiliency.IsRetryable(errs) && !errors.As(errs, &netlink.LinkNotFoundError{}) {
			d.logger.Warn(
				"Failed to remove old router IPs from cilium_host.",
				logfields.Error, errs,
				logfields.Attempt, retries,
			)
			return false, nil
		}
		return true, errs
	}
	if err := resiliency.Retry(ctx, 100*time.Millisecond, 3, gcHostIPsFn); err != nil {
		d.logger.Error("Restore of the cilium_host ips failed. Manual intervention is required to remove all other old IPs.", logfields.Error, err)
	}
}

// newDaemon creates and returns a new Daemon with the parameters set in c.
func newDaemon(ctx context.Context, cleaner *daemonCleanup, params *daemonParams) (*Daemon, *endpointRestoreState, error) {
	var err error

	bootstrapStats.daemonInit.Start()

	// EncryptedOverlay feature must check the TunnelProtocol if enabled, since
	// it only supports VXLAN right now.
	if option.Config.EncryptionEnabled() && option.Config.EnableIPSecEncryptedOverlay {
		if !option.Config.TunnelingEnabled() {
			return nil, nil, fmt.Errorf("EncryptedOverlay support requires VXLAN tunneling mode")
		}
		if params.TunnelConfig.EncapProtocol() != tunnel.VXLAN {
			return nil, nil, fmt.Errorf("EncryptedOverlay support requires VXLAN tunneling protocol")
		}
	}

	if option.Config.TunnelingEnabled() && params.TunnelConfig.UnderlayProtocol() == tunnel.IPv6 {
		if option.Config.EnableWireguard {
			return nil, nil, fmt.Errorf("WireGuard requires an IPv4 underlay")
		}
	}

	// IPAMENI IPSec is configured from Reinitialize() to pull in devices
	// that may be added or removed at runtime.
	if params.IPSecConfig.Enabled() &&
		!params.DaemonConfig.TunnelingEnabled() &&
		len(params.DaemonConfig.UnsafeDaemonConfigOption.EncryptInterface) == 0 &&
		// If devices are required, we don't look at the EncryptInterface, as we
		// don't load bpf_network in loader.reinitializeIPSec. Instead, we load
		// bpf_host onto physical devices as chosen by configuration.
		!params.DaemonConfig.AreDevicesRequired(params.KPRConfig, params.WireguardConfig.Enabled(), params.IPSecConfig.Enabled()) &&
		params.DaemonConfig.IPAM != ipamOption.IPAMENI {
		link, err := linuxdatapath.NodeDeviceNameWithDefaultRoute(params.Logger)
		if err != nil {
			return fmt.Errorf("Ipsec default interface lookup failed, consider \"encrypt-interface\" to manually configure interface. Err: %w", err)
		}
		params.DaemonConfig.UnsafeDaemonConfigOption.EncryptInterface = append(params.DaemonConfig.UnsafeDaemonConfigOption.EncryptInterface, link)
	}

	// Do the partial kube-proxy replacement initialization before creating BPF
	// maps. Otherwise, some maps might not be created (e.g. session affinity).
	// finishKubeProxyReplacementInit(), which is called later after the device
	// detection, might disable BPF NodePort and friends. But this is fine, as
	// the feature does not influence the decision which BPF maps should be
	// created.
	if err := params.KPRInitializer.InitKubeProxyReplacementOptions(); err != nil {
		return fmt.Errorf("unable to initialize kube-proxy replacement options: %w", err)
	}

	if params.K8sClientConfig.IsEnabled() {
		// Kubernetes demands that the localhost can always reach local
		// pods. Therefore unless the AllowLocalhost policy is set to a
		// specific mode, always allow localhost to reach local
		// endpoints.
		if params.DaemonConfig.UnsafeDaemonConfigOption.AllowLocalhost == option.AllowLocalhostAuto {
			params.DaemonConfig.UnsafeDaemonConfigOption.AllowLocalhost = option.AllowLocalhostAlways
			params.Logger.Info("k8s mode: Allowing localhost to reach local endpoints")
		}
	}

	// BPF masquerade depends on BPF NodePort, so the following checks should
	// happen after invoking initKubeProxyReplacementOptions().
	if params.DaemonConfig.MasqueradingEnabled() && params.DaemonConfig.EnableBPFMasquerade {
		var err error
		switch {
		case len(params.DaemonConfig.MasqueradeInterfaces) > 0:
			err = fmt.Errorf("BPF masquerade does not allow to specify devices via --%s (use --%s instead)",
				option.MasqueradeInterfaces, option.Devices)
		}
		if err != nil {
			return fmt.Errorf("unable to initialize BPF masquerade support: %w", err)
		}
		if params.DaemonConfig.EnableMasqueradeRouteSource {
			return fmt.Errorf("BPF masquerading to route source (--%s=\"true\") currently not supported with BPF-based masquerading (--%s=\"true\")", option.EnableMasqueradeRouteSource, option.EnableBPFMasquerade)
		}
	} else if params.DaemonConfig.EnableIPMasqAgent {
		return fmt.Errorf("BPF ip-masq-agent requires (--%s=\"true\" or --%s=\"true\") and --%s=\"true\"", option.EnableIPv4Masquerade, option.EnableIPv6Masquerade, option.EnableBPFMasquerade)
	} else if !params.DaemonConfig.MasqueradingEnabled() && params.DaemonConfig.EnableBPFMasquerade {
		return fmt.Errorf("BPF masquerade requires (--%s=\"true\" or --%s=\"true\")", option.EnableIPv4Masquerade, option.EnableIPv6Masquerade)
	}

	return nil
}

func configureDaemon(ctx context.Context, params daemonParams) error {
	if params.Clientset.IsEnabled() {
		bootstrapStats.k8sInit.Start()
		// Errors are handled inside WaitForCRDsToRegister. It will fatal on a
		// context deadline or if the context has been cancelled, the context's
		// error will be returned. Otherwise, it succeeded.
		if !params.DaemonConfig.DryMode {
			_, err := params.CRDSyncPromise.Await(ctx)
			if err != nil {
				return err
			}
		}

		if params.DaemonConfig.IPAM == ipamOption.IPAMClusterPool ||
			params.DaemonConfig.IPAM == ipamOption.IPAMMultiPool {
			// Create the CiliumNode custom resource. This call will block until
			// the custom resource has been created
			params.NodeDiscovery.UpdateCiliumNodeResource()
		}

		if err := agentK8s.WaitForNodeInformation(ctx, params.Logger, params.LocalNodeRes, params.LocalCiliumNodeRes); err != nil {
			return fmt.Errorf("unable to connect to get node spec from apiserver: %w", err)
		}

		bootstrapStats.k8sInit.End(true)
	}

	// The kube-proxy replacement and host-fw devices detection should happen after
	// establishing a connection to kube-apiserver, but before starting a k8s watcher.
	// This is because the device detection requires self (Cilium)Node object.

	rxn := params.DB.ReadTxn()
	drdName := ""
	directRoutingDevice, _ := params.DirectRoutingDevice.Get(ctx, rxn)
	if directRoutingDevice == nil {
		if params.DaemonConfig.AreDevicesRequired(params.KPRConfig, params.WGAgent.Enabled(), params.IPsecAgent.Enabled()) {
			// Fail hard if devices are required to function.
			return fmt.Errorf("unable to determine direct routing device. Use --%s to specify it", option.DirectRoutingDevice)
		}
	} else {
		drdName = directRoutingDevice.Name
		params.Logger.Info(
			"Direct routing device detected",
			option.DirectRoutingDevice, drdName,
		)
	}

	nativeDevices, _ := datapathTables.SelectedDevices(params.Devices, rxn)
	if err := params.KPRInitializer.FinishKubeProxyReplacementInit(nativeDevices, drdName); err != nil {
		return fmt.Errorf("failed to finalise LB initialization: %w", err)
	}
	if len(nativeDevices) == 0 && params.DaemonConfig.EnableHostFirewall {
		return fmt.Errorf("failed to determine host firewall's external facing device (use --%s to specify)", option.Devices)
	}

	// Launch the K8s watchers in parallel as we continue to process other
	// daemon options.
	// Some of the k8s watchers rely on option flags set above (specifically
	// EnableBPFMasquerade), so we should only start them once the flag values
	// are set.
	bootstrapStats.k8sInit.Start()
	params.K8sWatcher.InitK8sSubsystem(ctx)
	bootstrapStats.k8sInit.End(true)

	// Configure and start IPAM without using the configuration yet.
	configureAndStartIPAM(ctx, params)

	// restore endpoints before any IPs are allocated to avoid eventual IP
	// conflicts later on, otherwise any IP conflict will result in the
	// endpoint not being able to be restored.
	if err := params.EndpointRestorer.RestoreOldEndpoints(); err != nil {
		return err
	}

	// We must do this after IPAM because we must wait until the
	// K8s resources have been synced.
	if err := params.InfraIPAllocator.AllocateIPs(ctx); err != nil {
		return err
	}

	// Must occur after d.allocateIPs(), see GH-14245 and its fix.
	if params.DaemonConfig.EnableCiliumNodeCRD {
		params.NodeDiscovery.StartDiscovery(ctx)
	}

	// Annotation of the k8s node must happen after discovery of the
	// PodCIDR range and allocation of the health IPs.
	params.NodeDiscovery.AnnotateK8sNode(ctx)

	// Trigger refresh and update custom resource in the apiserver with all restored endpoints.
	// Trigger after nodeDiscovery.StartDiscovery to avoid custom resource update conflict.
	params.IPAM.RestoreFinished()

	// This needs to be done after the node addressing has been configured
	// as the node address is required as suffix.
	// well known identities have already been initialized above.
	// Ignore the channel returned by this function, as we want the global
	// identity allocator to run asynchronously.
	if params.DaemonConfig.IdentityAllocationMode != option.IdentityAllocationModeCRD ||
		params.Clientset.IsEnabled() {
		// **NOTE** The global identity allocator is not yet initialized here; that
		// happens below via InitIdentityAllocator(). Only the local identity
		// allocator is initialized here.
		identityAllocator: params.IdentityAllocator,
		ipcache:           params.IPCache,
		identityRestorer:  params.IdentityRestorer,
		policy:            params.Policy,
		idmgr:             params.IdentityManager,
		clustermesh:       params.ClusterMesh,
		monitorAgent:      params.MonitorAgent,
		bwManager:         params.BandwidthManager,
		endpointCreator:   params.EndpointCreator,
		endpointManager:   params.EndpointManager,
		endpointMetadata:  params.EndpointMetadata,
		k8sWatcher:        params.K8sWatcher,
		ipam:              params.IPAM,
		cniConfigManager:  params.CNIConfigManager,
		maglevConfig:      params.MaglevConfig,
		lbConfig:          params.LBConfig,
		kprCfg:            params.KPRConfig,
		ciliumHealth:      params.CiliumHealth,
	}

	// initialize endpointRestoreComplete channel as soon as possible so that subsystems
	// can wait on it to get closed and not block forever if they happen so start
	// waiting when it is not yet initialized (which causes them to block forever).
	if option.Config.RestoreState {
		d.endpointRestoreComplete = make(chan struct{})
		d.endpointInitialPolicyComplete = make(chan struct{})
	}

	// Collect CIDR identities from the "old" bpf ipcache and restore them
	// in to the metadata layer.
	if option.Config.RestoreState && !option.Config.DryMode {
		// this *must* be called before initMaps(), which will "hide"
		// the "old" ipcache.
		err := d.identityRestorer.RestoreLocalIdentities()
		if err != nil {
			d.logger.Warn("Failed to restore existing identities from the previous ipcache. This may cause policy interruptions during restart.", logfields.Error, err)
		}
	}

	bootstrapStats.daemonInit.End(true)

	// Stop all endpoints (its goroutines) on exit.
	cleaner.cleanupFuncs.Add(func() {
		d.logger.Info("Waiting for all endpoints' goroutines to be stopped.")
		var wg sync.WaitGroup

		eps := d.endpointManager.GetEndpoints()
		wg.Add(len(eps))

		for _, ep := range eps {
			go func(ep *endpoint.Endpoint) {
				ep.Stop()
				wg.Done()
			}(ep)
		}

		wg.Wait()
		d.logger.Info("All endpoints' goroutines stopped.")
	})

	// Open or create BPF maps.
	bootstrapStats.mapsInit.Start()
	err = d.initMaps()
	bootstrapStats.mapsInit.EndError(err)
	if err != nil {
		d.logger.Error("error while opening/creating BPF maps", logfields.Error, err)
		return nil, nil, fmt.Errorf("error while opening/creating BPF maps: %w", err)
	}

	debug.RegisterStatusObject("ipam", d.ipam)

	if option.Config.DNSPolicyUnloadOnShutdown {
		d.logger.Debug(
			"Registering cleanup function to unload DNS policies due to option",
			logfields.Option, option.DNSPolicyUnloadOnShutdown,
		)

		// add to pre-cleanup funcs because this needs to run on graceful shutdown, but
		// before the relevant subystems are being shut down.
		cleaner.preCleanupFuncs.Add(func() {
			// Stop k8s watchers
			d.logger.Info("Stopping k8s watcher")
			d.k8sWatcher.StopWatcher()

		// Iterate over the policy repository and remove L7 DNS part
		needsPolicyRegen := false
		removeL7DNSRules := func(pr policyAPI.Ports) error {
			portProtocols := pr.GetPortProtocols()
			if len(portProtocols) == 0 {
				return nil
			}
			portRule := pr.GetPortRule()
			if portRule == nil || portRule.Rules == nil {
				return nil
			}
			dnsRules := portRule.Rules.DNS
			params.Logger.Debug(
				"Found egress L7 DNS rules",
				logfields.PortProtocol, portProtocols[0],
				logfields.DNSRules, dnsRules,
			)

			// For security reasons, the L7 DNS policy must be a
			// wildcard in order to trigger this logic.
			// Otherwise we could invalidate the L7 security
			// rules. This means if any of the DNS L7 rules
			// have a matchPattern of * then it is OK to delete
			// the L7 portion of those rules.
			hasWildcard := false
			for _, dns := range dnsRules {
				if dns.MatchPattern == "*" {
					hasWildcard = true
					break
				}
			}
			if hasWildcard {
				portRule.Rules = nil
				needsPolicyRegen = true
			}
			return nil
		}

		params.Policy.Iterate(func(rule *policytypes.PolicyEntry) {
			_ = rule.L4.Iterate(removeL7DNSRules)
		})

		if !needsPolicyRegen {
			params.Logger.Info(
				"No policy recalculation needed to remove DNS rules due to option",
				logfields.Option, option.DNSPolicyUnloadOnShutdown,
			)
			return
		}

		// Bump revision to trigger policy recalculation
		params.Logger.Info(
			"Triggering policy recalculation to remove DNS rules due to option",
			logfields.Option, option.DNSPolicyUnloadOnShutdown,
		)
		params.Policy.BumpRevision()
		regenerationMetadata := &regeneration.ExternalRegenerationMetadata{
			Reason:            "unloading DNS rules on graceful shutdown",
			RegenerationLevel: regeneration.RegenerateWithoutDatapath,
		}
		wg := params.EndpointManager.RegenerateAllEndpoints(regenerationMetadata)
		wg.Wait()
		params.Logger.Info("All endpoints regenerated after unloading DNS rules on graceful shutdown")
	}
}
