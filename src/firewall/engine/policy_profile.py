from firewall.engine.policy_config import (
    CaptureContext,
    FlowLimits,
    ICMPSelector,
    PolicyConfig,
    PortRestriction,
    ServiceRule,
    SizeLimits,
    WindowLimits,
)

# --- DEFAULT PROFILE ---

LAN_NETWORK = "192.168.1.0/24"
SERVER_NETWORK = "192.0.2.0/24"      # TEST-NET-1
DNS_NETWORK = "198.51.100.0/24"      # TEST-NET-2

# structural checks enabled for academic checks
DEFAULT_FATAL_CHECKS = (
    "packet_length_consistency",
    "payload_length_consistency",
    "protocol_fields_consistency",
    "src_ip_format",
    "dst_ip_format",
    "ip_version_consistency",
    "ip_header_length",
    "ip_next_header_range",
    "ip_extension_headers_length",
    "ip_last_next_header_range",
    "ip_fragmentation_consistency",
    "tcp_ports_range",
    "tcp_header_length",
    "tcp_sequence_number_range",
    "tcp_ack_number_range",
    "udp_ports_range",
    "udp_length_consistency",
    "icmp_fields_completeness",
    "icmp_message_length",
)


def demo_profile() -> PolicyConfig:
    service_rules = (
        ServiceRule(
            rule_id="ALLOW_LAN_WEB",
            protocol="TCP",
            source_networks=(LAN_NETWORK,),
            destination_networks=(SERVER_NETWORK,),
            destination_ports=(80, 443),
            icmp_selectors=(),
            allow_replies=True,
        ),

        ServiceRule(
            rule_id="ALLOW_LAN_DNS",
            protocol="UDP",
            source_networks=(LAN_NETWORK,),
            destination_networks=(DNS_NETWORK,),
            destination_ports=(53,),
            icmp_selectors=(),
            allow_replies=True,
        ),

        ServiceRule(
            rule_id="ALLOW_ICMP_ECHO_REQUEST",
            protocol="ICMP",
            source_networks=(LAN_NETWORK,),
            destination_networks=(SERVER_NETWORK,),
            destination_ports=None,
            icmp_selectors=(ICMPSelector(type=8, code=0),),
        ),
        
        ServiceRule(
            rule_id="ALLOW_ICMP_ECHO_REPLY",
            protocol="ICMP",
            source_networks=(SERVER_NETWORK,),
            destination_networks=(LAN_NETWORK,),
            destination_ports=None,
            icmp_selectors=(ICMPSelector(type=0, code=0),),
        ),
    )

    # the default block is on the destination port; source blocks are separate
    blocked_destination_ports = (
        PortRestriction(rule_id="BLOCK_TCP_TELNET_DEST", protocol="TCP", port=23),
        PortRestriction(rule_id="BLOCK_TCP_RPC_DEST", protocol="TCP", port=135),
        PortRestriction(rule_id="BLOCK_TCP_NETBIOS_DEST", protocol="TCP", port=139),
        PortRestriction(rule_id="BLOCK_TCP_SMB_DEST", protocol="TCP", port=445),
        PortRestriction(rule_id="BLOCK_TCP_RDP_DEST", protocol="TCP", port=3389),
        PortRestriction(rule_id="BLOCK_UDP_RDP_DEST", protocol="UDP", port=3389),
    )

    return PolicyConfig(
        service_rules=service_rules,
        blocked_source_ports=(),
        blocked_destination_ports=blocked_destination_ports,
        blocked_networks=(),
        fatal_checks=DEFAULT_FATAL_CHECKS,
        # protocol-specific authorization checks remain mandatory in the engine
        # no additional capture-dependent checks are required by this profile
        required_checks=(),
        block_fragments=True,
        block_syn_fin=True,
        block_syn_rst=True,
        block_null_flags=True,
        block_special_sources=True,
        size_limits=SizeLimits(
            # optional: it depends on the MTU and requires explicit activation
            max_l3_length=None,
        ),
        flow_limits=FlowLimits(
            max_packets_per_second=1000.0,
            max_bytes_per_second=1_000_000.0,
            max_duration=300.0,
            max_flow_bytes=50_000_000,
        ),
        window_limits=WindowLimits(
            packet_flood_window=1.0,
            packet_flood_max=1000,
            syn_flood_window=1.0,
            syn_flood_max=100,
            echo_flood_window=1.0,
            echo_flood_max=20,
            port_scan_window=10.0,
            port_scan_max_ports=20,
            host_scan_window=10.0,
            host_scan_max_hosts=15,
            small_packet_window=1.0,
            small_packet_max=200,
            small_packet_max_size=80,
        ),
        capture_context=CaptureContext.LAN,
        boundary_source_networks=None,
        local_subnets=(LAN_NETWORK,),
    )
