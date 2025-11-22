use pnet::datalink::{self, Channel, Config, MacAddr, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::Packet;
use rayon::prelude::*;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use users::get_effective_uid;

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
            eprintln!("Failed to create datalink channel for {}: {}", interface.name, e);
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
    
    // MACアドレスとIPv4アドレスを持つ、ループバックでないインターフェースをフィルタリング
    let valid_interfaces: Vec<_> = interfaces
        .into_iter()
        .filter(|iface| {
            iface.mac.is_some() && !iface.is_loopback() && iface.ips.iter().any(|ip| ip.is_ipv4())
        })
        .collect();

    if valid_interfaces.is_empty() {
        eprintln!("No suitable network interface found.");
        return;
    }

    println!("Found {} suitable interface(s).", valid_interfaces.len());

    // 各インターフェースでスキャンを実行
    for interface in valid_interfaces {
        println!("\nScanning on interface: {}", interface.name);

        // インターフェースからIPv4ネットワーク情報を取得
        let Some(ipv4_network) = interface.ips.iter().find_map(|ip| {
            if let IpNetwork::V4(network) = ip {
                Some(network)
            } else {
                None
            }
        }) else {
            continue; // IPv4ネットワークが見つからなければ次へ
        };

        let source_ip = ipv4_network.ip();
        println!("  - Interface IP: {}", source_ip);
        println!("  - Network: {}", ipv4_network);
        println!("Scanning hosts... Please wait.");

        // ネットワーク内の全ホストIPアドレスをリストアップ (ネットワークアドレスとブロードキャストアドレスを除く)
        let ip_list: Vec<Ipv4Addr> = ipv4_network.iter().collect();
        
        // 並列でARPリクエストを送信
        let mut results: Vec<(Ipv4Addr, MacAddr)> = ip_list
            .into_par_iter()
            .filter_map(|target_ip| {
                // 自分自身のIPアドレスはスキップ
                if target_ip == source_ip {
                    return None;
                }
                // ARPリクエストを送信し、応答があればSome((ip, mac))を返す
                send_arp_request(&interface, source_ip, target_ip)
                    .map(|mac| (target_ip, mac))
            })
            .collect();
        
        // 自身のIPアドレスとMACアドレスを結果に追加
        if let Some(mac) = interface.mac {
            results.push((source_ip, mac));
        }

        // IPアドレスでソート
        results.sort_by_key(|(ip, _)| *ip);

        if results.is_empty() {
            println!("No devices found on this network.");
        } else {
            println!("\nScan complete. Found {} devices on network {}:", results.len(), ipv4_network);
            println!("{:<17} {}", "IP Address", "MAC Address");
            println!("{:-<17} {:-<17}", "", "");
            for (ip, mac) in results {
                println!("{:<17} {}", ip, mac);
            }
        }
    }
}