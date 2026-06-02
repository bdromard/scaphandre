use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
};

use sysinfo::NetworkData;

#[derive(Clone, Debug, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub enum IpVersion {
    Ipv4,
    Ipv6,
    Unknown,
}

struct IpPacket {
    version: IpVersion,
    protocol: Protocol,
}

impl IpPacket {
    fn new(data: &[u8]) -> Self {
        let version = data[0] >> 4;
        let ip_version = match version {
            4 => IpVersion::Ipv4,
            6 => IpVersion::Ipv6,
            _ => IpVersion::Unknown,
        };

        let protocol_as_bytes = data[9];

        let protocol = match protocol_as_bytes {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => Protocol::Unknown,
        };

        IpPacket {
            version: ip_version,
            protocol,
        }
    }
}

#[derive(Debug, PartialEq)]
struct Socket {
    inode: i32,
    process_name: String,
    protocol: Protocol,
}

impl Socket {
    pub fn new(process: &ProcessNetworkMetrics, inodes: &[i32], protocol: &Protocol) -> Self {
        let socket_inode = inodes
            .iter()
            .filter(|inode| process.sockets_inodes.contains(inode))
            .collect::<Vec<&i32>>()[0];

        Socket {
            inode: *socket_inode,
            process_name: process.name.clone(),
            protocol: protocol.to_owned().clone(),
        }
    }
}

struct NetworkInterface {
    name: String,
    total_received_bytes: u64,
    total_transmitted_bytes: u64,
}

impl NetworkInterface {
    fn new(sysinfo_interface: (&String, &NetworkData)) -> Self {
        NetworkInterface {
            name: sysinfo_interface.0.to_owned(),
            total_transmitted_bytes: sysinfo_interface.1.total_transmitted(),
            total_received_bytes: sysinfo_interface.1.total_received(),
        }
    }
}

pub struct ProcessNetworkMetrics {
    pub name: String,
    pub pid: u32,
    pub sockets_inodes: Vec<i32>,
    pub total_received_bytes: u64,
    pub total_transmitted_bytes: u64,
}

fn find_inodes_for_sockets(sockets_file: PathBuf) -> Vec<i32> {
    let sockets: Vec<String> = read_to_string(sockets_file)
        .unwrap()
        .lines()
        .map(|line| line.to_string())
        .collect();

    // Ignoring header in /proc/net/tcp{6} or /proc/net/udp{6} file
    let inodes: Vec<i32> = sockets[1..]
        .iter()
        .map(|socket| {
            socket.trim().split(" ").collect::<Vec<&str>>()[20]
                .parse::<i32>()
                .unwrap()
        })
        .collect();

    inodes
}

pub fn identify_psock_inodes(pid: u32, proc_path: &Path) -> Vec<i32> {
    let fd_path = proc_path.join("proc").join(pid.to_string()).join("fd");

    let slinks: Vec<String> = fd_path
        .read_dir()
        .unwrap()
        .filter(|entry| {
            let path = entry.as_ref().unwrap().path();
            path.is_symlink()
        })
        .map(|entry| {
            let link = entry.unwrap().path().read_link().unwrap();
            link.to_str().unwrap().to_string()
        })
        .collect();

    let sockets: Vec<String> = slinks
        .iter()
        .filter(|link| link.starts_with("socket"))
        .map(|socket| socket.to_string())
        .collect();

    let mut inodes: Vec<i32> = sockets
        .iter()
        .map(|socket| {
            socket
                .strip_prefix("socket:[")
                .unwrap()
                .strip_suffix("]")
                .unwrap()
                .parse::<i32>()
                .unwrap()
        })
        .collect();

    inodes.sort();
    inodes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn it_should_create_a_new_network_interface_from_sysinfo() {
        let network_interfaces = sysinfo::Networks::new_with_refreshed_list();

        network_interfaces.iter().for_each(|interface| {
            let scaph_net_interface = NetworkInterface::new(interface);

            assert_eq!(&scaph_net_interface.name, interface.0);
            assert_eq!(
                scaph_net_interface.total_received_bytes,
                interface.1.total_received()
            );
            assert_eq!(
                scaph_net_interface.total_transmitted_bytes,
                interface.1.total_transmitted()
            );
        });
    }

    #[test]
    fn it_should_identify_the_inodes_for_listening_tcp_sockets() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let tcp_sockets_fixture = Path::new(manifest_dir).join("tests/fixtures/tcp");
        let expected_inodes = vec![37312, 37313, 28907, 16344];

        let identified_inodes = find_inodes_for_sockets(tcp_sockets_fixture);

        assert_eq!(expected_inodes, identified_inodes);
    }

    #[test]
    fn it_should_identify_the_inodes_for_listening_udp_sockets() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let udp_sockets_fixture = Path::new(manifest_dir).join("tests/fixtures/udp");
        let expected_inodes = vec![28671, 17324, 20750, 31834];

        let identified_inodes = find_inodes_for_sockets(udp_sockets_fixture);

        assert_eq!(expected_inodes, identified_inodes);
    }

    #[test]
    fn it_should_identify_a_socket_for_a_given_process() {
        let identified_tcp_inodes = [37312, 37313, 28907, 16344];

        let process = ProcessNetworkMetrics {
            name: String::from("firefox"),
            pid: 123,
            sockets_inodes: vec![37312, 37313],
            total_received_bytes: 0,
            total_transmitted_bytes: 0,
        };

        let protocol = &Protocol::Tcp;

        let socket = Socket::new(&process, &identified_tcp_inodes, protocol);

        assert_eq!(socket.process_name, process.name);
        assert_eq!(socket.protocol, Protocol::Tcp);
        assert_eq!(socket.inode, 37312);
    }

    #[test]
    fn it_should_identify_an_ipv4_packet() {
        let packet_data_as_bytes: Vec<u8> = vec![
            69, 0, 0, 61, 92, 138, 64, 0, 64, 17, 170, 83, 10, 128, 31, 18, 10, 64, 0, 1, 144, 208,
            0, 53, 0, 41, 52, 13, 201, 243, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 99, 104, 97, 116, 6,
            104, 117, 98, 98, 108, 111, 3, 111, 114, 103, 0, 0, 1, 0, 1,
        ];

        let parsed_packet = IpPacket::new(&packet_data_as_bytes);

        assert_eq!(parsed_packet.version, IpVersion::Ipv4);
    }

    #[test]
    fn it_should_identify_an_ipv6_packet() {
        let packet_data_as_bytes: Vec<u8> = vec![
            96, 0, 0, 61, 92, 138, 64, 0, 64, 17, 170, 83, 10, 128, 31, 18, 10, 64, 0, 1, 144, 208,
            0, 53, 0, 41, 52, 13, 201, 243, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 99, 104, 97, 116, 6,
            104, 117, 98, 98, 108, 111, 3, 111, 114, 103, 0, 0, 1, 0, 1,
        ];

        let parsed_packet = IpPacket::new(&packet_data_as_bytes);

        assert_eq!(parsed_packet.version, IpVersion::Ipv6);
    }

    #[test]
    fn it_should_identify_the_udp_protocol_for_an_ip_packet() {
        let packet_data_as_bytes: Vec<u8> = vec![
            96, 0, 0, 61, 92, 138, 64, 0, 64, 17, 170, 83, 10, 128, 31, 18, 10, 64, 0, 1, 144, 208,
            0, 53, 0, 41, 52, 13, 201, 243, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 99, 104, 97, 116, 6,
            104, 117, 98, 98, 108, 111, 3, 111, 114, 103, 0, 0, 1, 0, 1,
        ];

        let parsed_packet = IpPacket::new(&packet_data_as_bytes);

        assert_eq!(parsed_packet.protocol, Protocol::Udp);
    }

    #[test]
    fn it_should_identify_the_tcp_protocol_for_an_ip_packet() {
        let packet_data_as_bytes: Vec<u8> = vec![
            96, 0, 0, 61, 92, 138, 64, 0, 64, 6, 170, 83, 10, 128, 31, 18, 10, 64, 0, 1, 144, 208,
            0, 53, 0, 41, 52, 13, 201, 243, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 99, 104, 97, 116, 6,
            104, 117, 98, 98, 108, 111, 3, 111, 114, 103, 0, 0, 1, 0, 1,
        ];

        let parsed_packet = IpPacket::new(&packet_data_as_bytes);

        assert_eq!(parsed_packet.protocol, Protocol::Tcp);
    }
}
