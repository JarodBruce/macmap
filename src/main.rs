use local_ip_address::local_ip;
use pnet::datalink::{self, Channel, Config, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::Packet;
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use rayon::prelude::*;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::{Duration, Instant};

fn ipv4_list(network_info: Vec<String>) -> Vec<String> {
    let network_addr_str = &network_info[3];
    let broadcast_addr_str = &network_info[4];

    let Ok(network_addr) = Ipv4Addr::from_str(network_addr_str) else {
        return vec![];
    };
    let Ok(broadcast_addr) = Ipv4Addr::from_str(broadcast_addr_str) else {
        return vec![];
    };

    let mut network_addr_u32 = u32::from(network_addr);
    let broadcast_addr_u32 = u32::from(broadcast_addr);

    let mut ip_address_list = Vec::new();
    network_addr_u32 += 1;

    if network_addr_u32 < broadcast_addr_u32 {
        for ip_int in network_addr_u32..broadcast_addr_u32 {
            ip_address_list.push(Ipv4Addr::from(ip_int).to_string());
        }
    }
    ip_address_list
}

fn get_network_broadcast() -> Option<Vec<String>> {
    let my_local_ip = match local_ip() {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("Failed to get local IP: {}", e);
            return None;
        }
    };

    let result = if let Ok(if_addrs) = get_if_addrs::get_if_addrs() {
        if_addrs.into_iter().find_map(|iface| {
            if let get_if_addrs::IfAddr::V4(ipv4_info) = iface.addr {
                if ipv4_info.ip == my_local_ip {
                    Some((iface.name, ipv4_info.ip, ipv4_info.netmask))
                } else {
                    None
                }
            } else {
                None
            }
        })
    } else {
        None
    };

    if let Some((name, ip, netmask)) = result {
        let ip_u32 = u32::from(ip);
        let netmask_u32 = u32::from(netmask);
        let network_addr_u32 = ip_u32 & netmask_u32;
        let network_address = Ipv4Addr::from(network_addr_u32);
        let broadcast_addr_u32 = network_addr_u32 | !netmask_u32;
        let broadcast_address = Ipv4Addr::from(broadcast_addr_u32);
        let info_vec = vec![
            name,
            ip.to_string(),
            netmask.to_string(),
            network_address.to_string(),
            broadcast_address.to_string(),
        ];
        Some(info_vec)
    } else {
        eprintln!("Could not find network interface for IP: {}", my_local_ip);
        None
    }
}

fn send_arp_request(
    interface: &NetworkInterface,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> Option<[u8; 6]> {
    let source_mac = interface.mac.unwrap();

    let config = Config {
        read_timeout: Some(Duration::from_millis(100)),
        ..Default::default()
    };

    let (mut tx, mut rx) = match datalink::channel(interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            // eprintln!は複数のスレッドから呼ばれる可能性があるため、デバッグ時には注意
            return None;
        }
        Err(_) => {
            // eprintln!("Failed to create datalink channel: {}", e);
            return None;
        }
    };

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(datalink::MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(datalink::MacAddr::broadcast());
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);
    ethernet_packet.set_payload(arp_packet.packet());

    if tx.send_to(ethernet_packet.packet(), None).is_none() {
        return None;
    }

    let start_time = Instant::now();
    let timeout = Duration::from_millis(100);

    while start_time.elapsed() < timeout {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth_packet) = EthernetPacket::new(packet) {
                    if eth_packet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp_reply) = ArpPacket::new(eth_packet.payload()) {
                            if arp_reply.get_sender_proto_addr() == target_ip
                                && arp_reply.get_operation() == ArpOperations::Reply
                            {
                                return Some(arp_reply.get_sender_hw_addr().into());
                            }
                        }
                    }
                }
            }
            Err(e) => {
                if e.kind() != std::io::ErrorKind::TimedOut {
                    break;
                }
            }
        }
    }
    // ARP応答がなかった場合でもダミーMACアドレスを返す
    Some([0, 0, 0, 0, 0, 0])
}

fn main() {
    match get_network_broadcast() {
        Some(network_info) => {
            let interfaces = datalink::interfaces();
            // loopbackでない、MACアドレスを持つ、IPv4アドレスを持つすべてのインターフェースを取得
            let valid_interfaces: Vec<_> = interfaces
                .into_iter()
                .filter(|iface| {
                    !iface.is_loopback()
                        && iface.mac.is_some()
                        && iface.ips.iter().any(|ip| ip.is_ipv4())
                })
                .collect();

            if valid_interfaces.is_empty() {
                eprintln!("No suitable network interface found.");
                return;
            }

            // すべての有効なインターフェースで並列スキャン
            for iface in valid_interfaces {
                let source_ip = iface
                    .ips
                    .iter()
                    .find_map(|ip| {
                        if let IpNetwork::V4(ipv4_network) = ip {
                            Some(ipv4_network.ip())
                        } else {
                            None
                        }
                    })
                    .expect("Interface should have an IPv4 address");

                println!("Scanning network... Please wait.");

                let ip_list = ipv4_list(network_info.clone());
                let mut results: Vec<(Ipv4Addr, datalink::MacAddr)> = ip_list
                    .into_par_iter()
                    .filter_map(|ip_str| {
                        let target_ip = Ipv4Addr::from_str(&ip_str).ok()?;
                        // 自分自身のIPアドレスはスキップ
                        if target_ip == source_ip {
                            return None;
                        }
                        send_arp_request(&iface, source_ip, target_ip)
                            .map(|mac| (target_ip, datalink::MacAddr::from(mac)))
                    })
                    .collect();

                // IPリストが空の場合は自分のIPとダミーMACを1件追加
                if results.is_empty() {
                    results.push((source_ip, datalink::MacAddr::from([0, 0, 0, 0, 0, 0])));
                }

                // 収集した結果をソートして表示
                results.sort_by_key(|(ip, _)| *ip);

                println!("Scan complete. Found {} devices:", results.len());
                for (ip, mac) in results {
                    println!("{}: {}", ip, mac);
                }
            }
        }
        None => {
            println!("Could not retrieve network information.");
        }
    }
}
