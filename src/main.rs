use pnet::datalink::{self, Channel, Config, MacAddr, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use users::get_effective_uid;

#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalEndpoint {
    interface_name: String,
    ip: Ipv4Addr,
    mac: MacAddr,
}

struct InterfaceScan {
    interface_name: String,
    source_ip: Ipv4Addr,
    source_mac: MacAddr,
    network: pnet::ipnetwork::Ipv4Network,
    results: Vec<(Ipv4Addr, MacAddr)>,
}

fn is_ignored_interface(interface: &NetworkInterface) -> bool {
    let name = interface.name.as_str();

    name.starts_with("docker")
        || name.starts_with("br-")
        || name.starts_with("veth")
        || name.starts_with("vmnet")
        || name.starts_with("bridge")
        || name.starts_with("tun")
        || name.starts_with("tap")
        || name.starts_with("utun")
}

fn primary_ipv4_network(interface: &NetworkInterface) -> Option<pnet::ipnetwork::Ipv4Network> {
    interface.ips.iter().find_map(|ip| match ip {
        IpNetwork::V4(network) if network.prefix() < 32 => Some(*network),
        _ => None,
    })
}

fn scan_interface(
    interface: &NetworkInterface,
    ipv4_network: pnet::ipnetwork::Ipv4Network,
) -> Option<InterfaceScan> {
    let source_mac = interface.mac?;
    let source_ip = ipv4_network.ip();

    println!("\nScanning on interface: {}", interface.name);
    println!("  - Interface IP: {}", source_ip);
    println!("  - Network: {}", ipv4_network);
    println!("Scanning hosts... Please wait.");

    let ip_list: Vec<Ipv4Addr> = ipv4_network.iter().collect();
    let discovered_hosts: Vec<(Ipv4Addr, MacAddr)> = ip_list
        .into_par_iter()
        .filter_map(|target_ip| {
            if target_ip == source_ip {
                return None;
            }

            send_arp_request(interface, source_ip, target_ip).map(|mac| (target_ip, mac))
        })
        .collect();

    let mut deduped_results = BTreeMap::new();
    for (ip, mac) in discovered_hosts {
        deduped_results.insert(ip, mac);
    }
    deduped_results.insert(source_ip, source_mac);

    Some(InterfaceScan {
        interface_name: interface.name.clone(),
        source_ip,
        source_mac,
        network: ipv4_network,
        results: deduped_results.into_iter().collect(),
    })
}

fn can_hide_scan(displayed_scan: &InterfaceScan, candidate_scan: &InterfaceScan) -> bool {
    displayed_scan
        .results
        .iter()
        .any(|(ip, mac)| *ip == candidate_scan.source_ip && *mac == candidate_scan.source_mac)
        || candidate_scan
            .results
            .iter()
            .any(|(ip, mac)| *ip == displayed_scan.source_ip && *mac == displayed_scan.source_mac)
}

fn send_arp_request(
    interface: &NetworkInterface,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Option<MacAddr> {
    let source_mac = interface.mac.expect("Interface should have a MAC address");

    let config = Config {
        read_timeout: Some(Duration::from_millis(200)), // 少しタイムアウトを延長
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            eprintln!("Unsupported channel type for interface {}", interface.name);
            return None;
        }
        Err(e) => {
            eprintln!(
                "Failed to create datalink channel for {}: {}",
                interface.name, e
            );
            return None;
        }
    };

    // ARPリクエストパケットの作成
    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    // イーサネットフレームの作成
    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    ethernet_packet.set_payload(arp_packet.packet());

    // パケットの送信
    if tx.send_to(ethernet_packet.packet(), None).is_none() {
        eprintln!("Failed to send ARP request for {}", target_ip);
        return None;
    }

    // ARPリプライの受信
    let start_time = Instant::now();
    let timeout = Duration::from_millis(200); // 送信処理のタイムアウトと合わせる

    while start_time.elapsed() < timeout {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth_packet) = EthernetPacket::new(packet) {
                    if eth_packet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp_reply) = ArpPacket::new(eth_packet.payload()) {
                            if arp_reply.get_sender_proto_addr() == target_ip
                                && arp_reply.get_operation() == ArpOperations::Reply
                            {
                                return Some(arp_reply.get_sender_hw_addr());
                            }
                        }
                    }
                }
            }
            Err(e) => {
                // タイムアウト以外のエラーはループを抜ける
                if e.kind() != std::io::ErrorKind::TimedOut {
                    // eprintln!("Error receiving packet: {}", e);
                    break;
                }
            }
        }
    }

    // タイムアウトした場合
    None
}

fn main() {
    if get_effective_uid() != 0 {
        eprintln!("This program must be run with root privileges. Try `sudo`.");
        std::process::exit(1);
    }
    println!("Searching for network interfaces...");
    let interfaces = datalink::interfaces();

    let valid_interfaces: Vec<_> = interfaces
        .into_iter()
        .filter_map(|iface| {
            let ipv4_network = primary_ipv4_network(&iface)?;

            if iface.mac.is_none() || iface.is_loopback() || is_ignored_interface(&iface) {
                return None;
            }

            Some((iface, ipv4_network))
        })
        .collect();

    if valid_interfaces.is_empty() {
        eprintln!("No suitable network interface found.");
        return;
    }

    println!("Found {} suitable interface(s).", valid_interfaces.len());

    let local_endpoints: Vec<LocalEndpoint> = valid_interfaces
        .iter()
        .filter_map(|(interface, ipv4_network)| {
            interface.mac.map(|mac| LocalEndpoint {
                interface_name: interface.name.clone(),
                ip: ipv4_network.ip(),
                mac,
            })
        })
        .collect();

    let mut all_scans = Vec::new();
    for (interface, ipv4_network) in &valid_interfaces {
        if let Some(scan) = scan_interface(interface, *ipv4_network) {
            all_scans.push(scan);
        }
    }

    let mut displayed_scans: Vec<&InterfaceScan> = Vec::new();
    for scan in &all_scans {
        let hidden_by: Vec<&InterfaceScan> = displayed_scans
            .iter()
            .copied()
            .filter(|displayed_scan| can_hide_scan(displayed_scan, scan))
            .collect();

        if hidden_by.is_empty() {
            displayed_scans.push(scan);
            continue;
        }

        let matching_interfaces: Vec<String> = hidden_by
            .iter()
            .flat_map(|displayed_scan| {
                local_endpoints.iter().filter_map(|endpoint| {
                    if endpoint.interface_name == scan.interface_name {
                        return None;
                    }

                    let displayed_sees_endpoint = displayed_scan
                        .results
                        .iter()
                        .any(|(ip, mac)| *ip == endpoint.ip && *mac == endpoint.mac);
                    let candidate_sees_displayed = scan.results.iter().any(|(ip, mac)| {
                        *ip == displayed_scan.source_ip && *mac == displayed_scan.source_mac
                    });

                    if displayed_sees_endpoint || candidate_sees_displayed {
                        Some(endpoint.interface_name.clone())
                    } else {
                        None
                    }
                })
            })
            .collect();

        if matching_interfaces.is_empty() {
            println!(
                "\nSkipping interface {} because it overlaps with an already displayed local interface.",
                scan.interface_name
            );
        } else {
            println!(
                "\nSkipping interface {} because it can already see local interface(s): {}.",
                scan.interface_name,
                matching_interfaces.join(", ")
            );
        }
    }

    for scan in displayed_scans {
        if scan.results.is_empty() {
            println!("No devices found on this network.");
            continue;
        }

        println!(
            "\nScan complete. Found {} devices on network {}:",
            scan.results.len(),
            scan.network
        );
        println!("{:<17} {}", "IP Address", "MAC Address");
        println!("{:-<17} {:-<17}", "", "");
        for (ip, mac) in &scan.results {
            println!("{:<17} {}", ip, mac);
        }
    }
}
