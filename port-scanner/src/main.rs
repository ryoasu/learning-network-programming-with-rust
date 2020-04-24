extern crate dotenv;
extern crate rayon;
#[macro_use]
extern crate log;

use dotenv::dotenv;
use pnet::packet::{ip, tcp};
use pnet::transport::{self, TransportChannelType, TransportProtocol};
use std::collections::HashMap;
use std::process;
use std::{env, net, thread, time};

const TCP_SIZE: usize = 20;

#[derive(Debug)]
struct PacketInfo {
    my_ipaddr: net::Ipv4Addr,
    target_ipaddr: net::Ipv4Addr,
    my_port: u16,
    maximum_port: u16,
    scan_type: ScanType,
}

// Copy型を継承することで、代入や関数の引数として渡す際に、moveするのではなく値のコピーを渡す
// Copy型にするときは前提としてClone型も同時に実装する
#[derive(Copy, Clone, Debug)]
enum ScanType {
    Syn = tcp::TcpFlags::SYN as isize,
    Fin = tcp::TcpFlags::FIN as isize,
    Xmas = tcp::TcpFlags::FIN as isize | tcp::TcpFlags::URG as isize | tcp::TcpFlags::PSH as isize,
    Null = 0,
}

fn main() {
    env::set_var("RUST_LOG", "debug");
    env_logger::init();

    // コマンドライン引数からip addressとscan typeを取得
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        error!("Bud number of arguments. [ipaddr] [scantype]");
        process::exit(1);
    }

    // dotenvから環境変数を読み込む
    dotenv().ok();
    // 対象となる環境変数をHashMapとして取り出す
    let my_info: HashMap<String, String> = env::vars()
        .filter(|(k, _)| {
            [
                "MY_IPADDR".to_string(),
                "MY_PORT".to_string(),
                "MAXIMUM_PORT_NUM".to_string(),
            ]
            .contains(&k)
        })
        .collect();

    // myInfoとargsからPacketInfo型のデータを作成
    let packet_info = PacketInfo {
        my_ipaddr: my_info["MY_IPADDR"].parse().expect("Invalid my ipaddr"),
        target_ipaddr: args[1].parse().expect("Invalid target ipaddr"),
        my_port: my_info["MY_PORT"].parse().expect("Invalid my port number"),
        maximum_port: my_info["MAXIMUM_PORT_NUM"]
            .parse()
            .expect("Invalid maximum port num"),
        scan_type: match args[2].as_str() {
            "sS" => ScanType::Syn,
            "sF" => ScanType::Fin,
            "sX" => ScanType::Xmas,
            "sN" => ScanType::Null,
            _ => {
                error!("Undifined scan method, only accept [sS|sF|sX|sN].");
                process::exit(1);
            }
        },
    };

    println!("{:?}", packet_info);

    // トランスポート層のチャンネルを開く
    // 内部的にはソケット
    let (mut ts, mut tr) = transport::transport_channel(
        1024,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(ip::IpNextHeaderProtocols::Tcp)),
    )
    .expect("Failed to open channel");

    rayon::join(
        || send_packet(&mut ts, &packet_info),
        || receive_packets(&mut tr, &packet_info).expect("Failed receive packets"),
    );
}

fn send_packet(ts: &mut transport::TransportSender, packet_info: &PacketInfo) {
    // パケットを作成
    let mut packet = create_packet(packet_info);
    for i in 1..=packet_info.maximum_port {
        let mut tcp_header = tcp::MutableTcpPacket::new(&mut packet).unwrap();
        // 送信先のポートを指定
        reregister_destination_port(i, &mut tcp_header, packet_info);
        // sleepを入れないとターゲットのルーターによってはパケットが消失してしまう
        thread::sleep(time::Duration::from_millis(5));
        // パケットの送信
        ts.send_to(tcp_header, net::IpAddr::V4(packet_info.target_ipaddr))
            .expect("failed to send");
    }
}

fn receive_packets(
    tr: &mut transport::TransportReceiver,
    packet_info: &PacketInfo,
) -> Result<(), failure::Error> {
    let mut reply_ports = Vec::new();
    let mut packet_iter = transport::tcp_packet_iter(tr);
    loop {
        // macOS Mojave (10.14.6)だと、packet_iter.next()が返って来ず止まる。
        // Debian 10.3では動作確認済み
        let tcp_packet = match packet_iter.next() {
            Ok((tcp_packet, _)) => {
                if tcp_packet.get_destination() != packet_info.my_port {
                    continue;
                }
                tcp_packet
            }
            Err(_) => continue,
        };
        let target_port = tcp_packet.get_source();
        match packet_info.scan_type {
            // SYNスキャンでレシーブしたパケットのフラグがSYN|ACKだったら、そのportは開いている
            ScanType::Syn => {
                if tcp_packet.get_flags() == tcp::TcpFlags::SYN | tcp::TcpFlags::ACK {
                    println!("port {} is open", target_port);
                }
            }
            // FIN, Xmas, NULLスキャンなら
            ScanType::Fin | ScanType::Xmas | ScanType::Null => {
                reply_ports.push(target_port);
            }
        }
        // スキャン対象の最後のポートまで繰り返す
        // [手抜き実装]
        // TCPのフロー制御や再送制御の実装まではしていないので、その返答がそもそも返ってくるか、
        // 返ってくるとしても本当に最後のレスポンスかということがわからない
        if target_port != packet_info.maximum_port {
            continue;
        }
        match packet_info.scan_type {
            ScanType::Fin | ScanType::Xmas | ScanType::Null => {
                for i in 1..=packet_info.maximum_port {
                    if reply_ports.iter().find(|&&x| x == i).is_none() {
                        println!("port {} is open", i);
                    }
                }
            }
            _ => {}
        }
        return Ok(());
    }
}

fn create_packet(packet_info: &PacketInfo) -> [u8; TCP_SIZE] {
    let mut tcp_buffer = [0u8; TCP_SIZE];
    let mut tcp_header = tcp::MutableTcpPacket::new(&mut tcp_buffer[..]).unwrap();
    tcp_header.set_source(packet_info.my_port);
    tcp_header.set_data_offset(5);
    tcp_header.set_flags(packet_info.scan_type as u16);
    tcp_header.set_checksum(tcp::ipv4_checksum(
        &tcp_header.to_immutable(),
        &packet_info.my_ipaddr,
        &packet_info.target_ipaddr,
    ));

    tcp_buffer
}

fn reregister_destination_port(
    target: u16,
    tcp_header: &mut tcp::MutableTcpPacket,
    packet_info: &PacketInfo,
) {
    tcp_header.set_destination(target);
    tcp_header.set_checksum(tcp::ipv4_checksum(
        &tcp_header.to_immutable(),
        &packet_info.my_ipaddr,
        &packet_info.target_ipaddr,
    ));
}
