use std::{
    fs::read_to_string,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
};

use pcap::{Active, Capture, Device};
use sysinfo::{IpNetwork, NetworkData};

const TCP_SOCKETS_FILE: &str = "/proc/net/tcp";
const TCP6_SOCKETS_FILE: &str = "/proc/net/tcp6";
const UDP_SOCKETS_FILE: &str = "/proc/net/udp";
const UDP6_SOCKETS_FILE: &str = "/proc/net/udp6";

#[derive(Debug, PartialEq)]
pub enum PacketError {
    OptionsFieldError,
    FilteredPacket,
}

#[derive(Debug, PartialEq)]
pub enum ParsingError {
    UnparsablePort,
    UnparsableIpAddress,
}

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

#[derive(Clone, Debug, PartialEq)]
pub enum Direction {
    Outgoing,
    Incoming,
    Local,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PacketType {
    Ethernet,
    RawIp,
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub enum EtherType {
    VlanTagged,
    NotVlanTagged,
}

struct Packet {
    datalink_type: i32,
    data: Vec<u8>,
    packet_type: Option<PacketType>,
}

/// This structure is used to first distinguish between Ethernet frames and raw IP packets ;
/// depending on the datalink type at the link layer, pcap will either return one or the other.
/// pcap can return the datalink type for the monitored network interface, and it is therefore used
/// in identifying the packet type and returning the payload.
impl Packet {
    fn new(datalink_type: &i32, data: &[u8]) -> Self {
        let mut packet = Packet {
            datalink_type: datalink_type.to_owned(),
            data: data.to_owned(),
            packet_type: None,
        };
        let packet_type = packet.identify();
        packet.packet_type = Some(packet_type);
        packet
    }

    fn identify(&self) -> PacketType {
        match self.datalink_type {
            1 => PacketType::Ethernet,
            // 12 (RawIp without link layer), 101 (DLT_RAW), 228 (DLT_IPV4), 229 (DLT_IPV6) all
            //    indicate a raw IP packet.
            12 | 101 | 228 | 229 => PacketType::RawIp,
            _ => PacketType::Unknown,
        }
    }

    fn payload(&self) -> Vec<u8> {
        match self.packet_type.clone().unwrap() {
            PacketType::Ethernet => {
                let ethertype = self.parse_ethertype();
                match ethertype {
                    EtherType::NotVlanTagged => self.data[14..].to_vec(),
                    EtherType::VlanTagged => self.data[18..].to_vec(),
                }
            }
            PacketType::RawIp => self.data.to_vec(),
            PacketType::Unknown => todo!(),
        }
    }

    fn parse_ethertype(&self) -> EtherType {
        let data = &self.data;

        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        match ethertype {
            // 0x8100 indicates VLAN-tagging, and therefore a 18-byte Ethernet frame header
            33024 => EtherType::VlanTagged,
            // For the moment, we do not have to pay too much attention to all possible other
            // values, as they will all indicate a 14-byte Ethernet frame header
            _ => EtherType::NotVlanTagged,
        }
    }
}

#[derive(Debug)]
struct IpPacket {
    version: IpVersion,
    protocol: Protocol,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    data: Vec<u8>,
}

impl IpPacket {
    fn new(data: &[u8]) -> Result<Self, PacketError> {
        let version = data[0] >> 4;
        let ip_version = match version {
            4 => IpVersion::Ipv4,
            6 => IpVersion::Ipv6,
            _ => IpVersion::Unknown,
        };

        if ip_version == IpVersion::Ipv4 {
            // Internet Header Length in IPv4 packet is either 5 or more. If it is more than 5, it
            // means the Options Field is present. Due to security concerns with IPv4 options,
            // there are few use cases for the Options field for applications across networks,
            // therefore we are ignoring this kind of packet here for now.
            let ihl = data[0] & 0xF;

            let is_options_field_present = !matches!(ihl, 5);

            if is_options_field_present {
                return Err(PacketError::OptionsFieldError);
            }
        }

        let protocol_as_bytes = match ip_version {
            IpVersion::Ipv4 => Some(data[9]),
            IpVersion::Ipv6 => Some(data[6]),
            IpVersion::Unknown => None,
        };

        let protocol = match protocol_as_bytes
            .expect("It should contain a byte specifying the used protocol")
        {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => Protocol::Unknown,
        };

        let source_ip = match ip_version {
            IpVersion::Ipv4 => Some(IpAddr::V4(Ipv4Addr::new(
                data[12], data[13], data[14], data[15],
            ))),
            IpVersion::Ipv6 => Some(IpAddr::V6(Ipv6Addr::new(
                u16::from_be_bytes([data[8], data[9]]),
                u16::from_be_bytes([data[10], data[11]]),
                u16::from_be_bytes([data[12], data[13]]),
                u16::from_be_bytes([data[14], data[15]]),
                u16::from_be_bytes([data[16], data[17]]),
                u16::from_be_bytes([data[18], data[19]]),
                u16::from_be_bytes([data[20], data[21]]),
                u16::from_be_bytes([data[22], data[23]]),
            ))),
            _ => None,
        };

        let destination_ip = match ip_version {
            IpVersion::Ipv4 => Some(IpAddr::V4(Ipv4Addr::new(
                data[16], data[17], data[18], data[19],
            ))),
            IpVersion::Ipv6 => Some(IpAddr::V6(Ipv6Addr::new(
                u16::from_be_bytes([data[24], data[25]]),
                u16::from_be_bytes([data[26], data[27]]),
                u16::from_be_bytes([data[28], data[29]]),
                u16::from_be_bytes([data[30], data[31]]),
                u16::from_be_bytes([data[32], data[33]]),
                u16::from_be_bytes([data[34], data[35]]),
                u16::from_be_bytes([data[36], data[37]]),
                u16::from_be_bytes([data[38], data[39]]),
            ))),
            _ => None,
        };

        Ok(IpPacket {
            version: ip_version,
            protocol,
            source_ip: source_ip.expect("It should contain an IP address"),
            destination_ip: destination_ip.expect("It should contain an IP address"),
            data: data.to_vec(),
        })
    }
}

/// This structure represents either a TCP or UDP packet. For the relevant data needed to estimate,
/// the outgoing or incoming traffic per process, the packet parsing logic is the same. Depending
/// on future needs, this might evolve to a trait with a different parsing logic for each protocol.
#[derive(Clone, Debug, PartialEq)]
pub struct TransportLayerPacket {
    protocol: Protocol,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    source_address: Option<SocketAddr>,
    destination_address: Option<SocketAddr>,
    size: u64,
    data: Vec<u8>,
}

impl TransportLayerPacket {
    fn new(ip_packet: &IpPacket) -> Result<Self, PacketError> {
        let protocol = &ip_packet.protocol;

        if *protocol == Protocol::Unknown {
            return Err(PacketError::FilteredPacket);
        }

        let source_ip = &ip_packet.source_ip;
        let destination_ip = &ip_packet.destination_ip;

        let packet = &ip_packet.data[20..];
        Ok(TransportLayerPacket {
            protocol: protocol.to_owned(),
            source_ip: source_ip.to_owned(),
            destination_ip: destination_ip.to_owned(),
            source_address: None,
            destination_address: None,
            size: packet.len() as u64,
            data: packet.to_owned(),
        })
    }

    // UDP and TCP packets contain both ports in their header in the same location.
    fn parse(&mut self) {
        let packet = &self.data.to_owned();

        let source_port = u16::from_be_bytes([packet[0], packet[1]]);
        let destination_port = u16::from_be_bytes([packet[2], packet[3]]);

        let source_address = SocketAddr::new(self.source_ip, source_port);
        let destination_address = SocketAddr::new(self.destination_ip, destination_port);

        self.source_address = Some(source_address);
        self.destination_address = Some(destination_address);
    }
}

/// This structure contains either a TCP(6) or UDP(6) listening socket, as parsed from the
/// /proc/net/tcp(6) or /proc/net(6) files. It is meant to be allocated to a specific network
/// interface.
#[derive(Clone, Debug, PartialEq)]
pub struct Socket {
    inode: i32,
    process_name: Option<String>,
    pid: Option<u32>,
    protocol: Option<Protocol>,
    source_ip: Option<IpAddr>,
    destination_ip: Option<IpAddr>,
    source_port: Option<u32>,
    destination_port: Option<u32>,
    direction: Option<Direction>,
    packets: Vec<TransportLayerPacket>,
    app_packets_size: Option<u64>,
}

impl Socket {
    pub fn new(
        inode: i32,
        source_ip: IpAddr,
        destination_ip: IpAddr,
        source_port: u32,
        destination_port: u32,
    ) -> Self {
        Socket {
            inode,
            process_name: None,
            pid: None,
            protocol: None,
            source_ip: Some(source_ip),
            destination_ip: Some(destination_ip),
            source_port: Some(source_port),
            destination_port: Some(destination_port),
            direction: None,
            packets: vec![],
            app_packets_size: None,
        }
    }

    /// A socket must have a unique process to which it is associated.
    fn identify_process(&mut self, processes: Vec<&ProcessNetworkMetrics>) {
        let process: Vec<&&ProcessNetworkMetrics> = processes
            .iter()
            .filter(|process| {
                process
                    .sockets_inodes
                    .clone()
                    .unwrap()
                    .contains(&self.inode)
            })
            .collect();
        if !process.is_empty() {
            self.process_name = Some(process[0].name.clone());
            self.pid = Some(process[0].pid);
        }
    }

    fn filter_packet(&mut self, packet: &IpPacket) {
        if packet.source_ip == self.source_ip.unwrap()
            && packet.destination_ip == self.destination_ip.unwrap()
        {
            let maybe_transport_packet = TransportLayerPacket::new(packet);
            match maybe_transport_packet {
                Ok(packet) => self.packets.push(packet),
                Err(packet_error) => {
                    eprintln!("Unhandled protocol! The packet has been filtered: {packet_error:?}")
                }
            }
        }
    }

    fn set_direction(&mut self, local_ips: &[IpAddr]) {
        let source_ip = self.source_ip.unwrap();
        let destination_ip = self.destination_ip.unwrap();
        let direction = get_direction(&source_ip, &destination_ip, local_ips);

        self.direction = Some(direction);
    }

    fn evaluate_packets_size(&mut self) {
        let total_size = self
            .packets
            .clone()
            .iter()
            .map(|packet| {
                let size = identify_app_packet_size(&packet.data, self.protocol.clone().unwrap());
                size as u64
            })
            .sum();
        self.app_packets_size = Some(total_size);
    }
}

/// This structure contains the relevant information for a network interface (wired, wireless...).
/// It holds the sockets through which a connection is established, and these sockets are meant to
/// be continually updated at runtime.
///
pub struct NetworkInterface {
    name: String,
    total_received_bytes: u64,
    total_transmitted_bytes: u64,
    ip_networks: Vec<IpNetwork>,
    sockets: Vec<Socket>,
    packet_capture: Option<Capture<Active>>,
}

impl NetworkInterface {
    fn new(sysinfo_interface: (&String, &NetworkData)) -> Self {
        NetworkInterface {
            name: sysinfo_interface.0.to_owned(),
            total_transmitted_bytes: sysinfo_interface.1.total_transmitted(),
            total_received_bytes: sysinfo_interface.1.total_received(),
            ip_networks: sysinfo_interface.1.ip_networks().to_vec(),
            sockets: vec![],
            packet_capture: None,
        }
    }

    fn identify_sockets(&mut self, sockets_file: &Path) {
        let local_ips: Vec<IpAddr> = self
            .ip_networks
            .iter()
            .map(|network| network.addr)
            .collect();
        let sockets_lines: Vec<String> = read_to_string(sockets_file)
            .unwrap()
            .lines()
            .map(|line| line.to_string())
            .collect();

        // Checking that the source IP address is among the identified IP adresses linked
        // to a network interface. If so, create a socket for this network interface.
        let sockets: Vec<Socket> = sockets_lines[1..]
            .iter()
            .filter(|line| {
                let formatted_line = line.trim().split(" ").collect::<Vec<&str>>();
                let source_ip =
                    parse_address_from_hex(formatted_line[1].split(":").collect::<Vec<&str>>()[0])
                        .expect("It should contain the source IP address");
                local_ips.contains(&source_ip)
            })
            .map(|line| {
                let formatted_line = line.trim().split(" ").collect::<Vec<&str>>();
                let full_source_address = formatted_line[1].split(":").collect::<Vec<&str>>();
                let source_ip = parse_address_from_hex(full_source_address[0])
                    .expect("It should contain the source IP address.");

                let full_destination_address = formatted_line[2].split(":").collect::<Vec<&str>>();
                let destination_ip = parse_address_from_hex(full_destination_address[0])
                    .expect("It should contain the destination IP address.");

                let source_port = parse_port_from_hex(full_source_address[1])
                    .expect("It should contain the source port.");
                let destination_port = parse_port_from_hex(full_destination_address[1])
                    .expect("It should contain the destination port.");

                let inode = formatted_line[20]
                    .parse::<i32>()
                    .expect("It should parse the socket inode.");

                Socket::new(
                    inode,
                    source_ip,
                    destination_ip,
                    source_port,
                    destination_port,
                )
            })
            .collect();

        sockets.iter().for_each(|s| self.sockets.push(s.clone()));
    }

    pub fn capture_packets(&mut self) {
        let interface_name = &self.name;
        let devices = Device::list().unwrap();

        let pcap_device = devices
            .iter()
            .filter(|dev| dev.name == *interface_name)
            .collect::<Vec<&Device>>()[0];

        let capture = Capture::from_device(pcap_device.to_owned())
            .expect("It should allow capturing packets from network device.")
            .open()
            .expect("It should open the capture handle.");

        self.packet_capture = Some(capture);
    }
}

/// This structure contains the relevant information about a process network metrics. Scaphandre
/// already identifies processes at runtime ; this could be used either to update the exposed
/// information for each process, or as a separate object.
pub struct ProcessNetworkMetrics {
    pub name: String,
    pub pid: u32,
    pub sockets_inodes: Option<Vec<i32>>,
    pub total_received_bytes: u64,
    pub total_transmitted_bytes: u64,
}

impl ProcessNetworkMetrics {
    pub fn new(name: &str, pid: u32) -> Self {
        ProcessNetworkMetrics {
            name: name.to_string(),
            pid,
            sockets_inodes: None,
            total_received_bytes: 0,
            total_transmitted_bytes: 0,
        }
    }

    /// Each process can be associated to several sockets. For each process, inodes in
    /// /proc/<pid>/fd can be associated to a socket as a symbolic link, and this can be done by parsing that directory.
    pub fn identify_psock_inodes(&mut self, proc_path: &Path) {
        let fd_path = proc_path.join("proc").join(self.pid.to_string()).join("fd");

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
        self.sockets_inodes = Some(inodes);
    }

    pub fn update_traffic(&mut self, sockets: &[Socket]) {
        let incoming_sockets: Vec<&Socket> = sockets
            .iter()
            .filter(|socket| socket.direction == Some(Direction::Incoming))
            .collect();

        let outgoing_sockets: Vec<&Socket> = sockets
            .iter()
            .filter(|socket| socket.direction == Some(Direction::Outgoing))
            .collect();

        let total_received_traffic: u64 = incoming_sockets
            .iter()
            .map(|socket| socket.app_packets_size.unwrap())
            .sum();

        let total_transmitted_traffic: u64 = outgoing_sockets
            .iter()
            .map(|socket| socket.app_packets_size.unwrap())
            .sum();

        self.total_received_bytes += total_received_traffic;
        self.total_transmitted_bytes += total_transmitted_traffic;
    }
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

fn parse_address_from_hex(hex_string: &str) -> Result<IpAddr, ParsingError> {
    let string_length = hex_string.len();

    match string_length {
        8 => Ok(IpAddr::V4(parse_ipv4(hex_string))),
        32 => Ok(IpAddr::V6(parse_ipv6(hex_string))),
        _ => Err(ParsingError::UnparsableIpAddress),
    }
}

fn parse_ipv4(hex_string: &str) -> Ipv4Addr {
    let characters = hex_string.chars().collect::<Vec<char>>();
    let bytes: Vec<u8> = characters
        .chunks(2)
        .map(|chunk| u8::from_str_radix(format!("{}{}", chunk[0], chunk[1]).as_str(), 16).unwrap())
        .collect();

    // Order is little-endian for IPv4
    Ipv4Addr::new(bytes[3], bytes[2], bytes[1], bytes[0])
}

fn parse_ipv6(hex_string: &str) -> Ipv6Addr {
    let characters = hex_string.chars().collect::<Vec<char>>();
    let bytes: Vec<u16> = characters
        .chunks(4)
        .map(|chunk| {
            u16::from_str_radix(
                format!("{}{}{}{}", chunk[0], chunk[1], chunk[2], chunk[3]).as_str(),
                16,
            )
            .unwrap()
        })
        .collect();

    Ipv6Addr::new(
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    )
}

fn parse_port_from_hex(hex_string: &str) -> Result<u32, ParsingError> {
    let hex_string_length = hex_string.len();

    match hex_string_length {
        4 => {
            let port = u16::from_str_radix(hex_string, 16).unwrap();
            Ok(port as u32)
        }
        _ => Err(ParsingError::UnparsablePort),
    }
}

fn identify_app_packet_size(data: &[u8], protocol: Protocol) -> u32 {
    let size = match protocol {
        Protocol::Tcp => {
            let total_packet_size = (data.len() * 8) as u32;
            let tcp_header_size = (data[12] >> 4) as u32;
            Ok(total_packet_size - (tcp_header_size * 32))
        }
        Protocol::Udp => {
            let total_packet_size = (data.len() * 8) as u32;
            let udp_header_size = 16;
            Ok(total_packet_size - udp_header_size)
        }
        Protocol::Unknown => Err("Not a parsable protocol"),
    };

    size.unwrap()
}

/// Identifying the traffic direction, in order to allocate the relevant traffic throughput to a
/// process receiving or transmitting bytes. Some applications can use TCP / UDP sockets for local
/// traffic. These local sockets should be ignored at the moment.
fn get_direction(source_ip: &IpAddr, direction_ip: &IpAddr, local_ips: &[IpAddr]) -> Direction {
    match local_ips.contains(source_ip) {
        true => match local_ips.contains(direction_ip) {
            true => Direction::Local,
            false => Direction::Outgoing,
        },
        false => Direction::Incoming,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        error::Error,
        net::{IpAddr, Ipv4Addr},
        path::Path,
    };

    fn ethernet_frame() -> Vec<u8> {
        vec![
            51, 51, 255, 96, 226, 40, 112, 252, 143, 147, 10, 214, 134, 221, 69, 0, 0, 61, 92, 138,
            64, 0, 64, 17, 170, 127, 0, 0, 1, 8, 8, 8, 8, 1, 144, 208, 0, 53, 0, 41, 52, 13, 201,
            243, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 99, 104, 97, 116, 6, 104, 117, 98, 98, 108, 111,
            3, 111, 114, 103, 0, 0, 1, 0, 1,
        ]
    }

    fn ethernet_frame_vlan_tagged() -> Vec<u8> {
        vec![
            51, 51, 255, 96, 226, 40, 112, 252, 143, 147, 10, 214, 129, 0, 0, 100, 8, 0, 69, 0, 0,
            61, 92, 138, 64, 0, 64, 17, 170, 127, 0, 0, 1, 8, 8, 8, 8, 1, 144, 208, 0, 53, 0, 41,
            52, 13, 201, 243, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 99, 104, 97, 116, 6, 104, 117, 98,
            98, 108, 111, 3, 111, 114, 103, 0, 0, 1, 0, 1,
        ]
    }

    fn ipv4_packet_bytes(protocol: Protocol) -> Vec<u8> {
        match protocol {
            Protocol::Udp => vec![
                69, 0, 0, 61, 92, 138, 64, 0, 64, 17, 170, 127, 0, 0, 1, 8, 8, 8, 8, 1, 144, 208,
                0, 53, 0, 41, 52, 13, 201, 243, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 99, 104, 97, 116,
                6, 104, 117, 98, 98, 108, 111, 3, 111, 114, 103, 0, 0, 1, 0, 1,
            ],
            Protocol::Tcp => vec![
                69, 0, 1, 72, 233, 36, 64, 0, 64, 6, 67, 142, 127, 0, 0, 1, 8, 8, 8, 8, 208, 234,
                1, 187, 247, 89, 28, 109, 222, 186, 190, 253, 128, 24, 95, 247, 14, 56, 0, 0, 1, 1,
                8, 10, 211, 48, 238, 16, 146, 224, 159, 152, 23, 3, 3, 1, 15, 36, 159, 112, 182, 7,
                26, 40, 78, 203, 40, 151, 146, 172, 45, 76, 156, 222, 103, 188, 89, 211, 164, 138,
                175, 127, 39, 183, 159, 3, 239, 194, 49, 100, 17, 178, 149, 0, 116, 121, 15, 15,
                97, 213, 232, 88, 73, 50, 243, 176, 251, 229, 143, 227, 108, 207, 30, 30, 160, 237,
                133, 132, 80, 177, 238, 32, 19, 16, 204, 111, 159, 130, 171, 81, 98, 216, 128, 206,
                155, 146, 206, 157, 112, 216, 70, 170, 66, 246, 171, 12, 234, 161, 177, 53, 78,
                180, 237, 128, 128, 210, 177, 76, 248, 183, 37, 218, 30, 188, 99, 190, 113, 13, 94,
                29, 109, 206, 38, 7, 119, 107, 62, 125, 60, 145, 96, 64, 144, 101, 104, 132, 67,
                170, 243, 236, 37, 115, 40, 24, 170, 103, 24, 113, 24, 228, 211, 39, 155, 211, 63,
                173, 179, 112, 31, 143, 168, 166, 122, 117, 12, 95, 7, 4, 33, 25, 192, 143, 249, 1,
                18, 230, 163, 115, 224, 33, 169, 39, 52, 70, 212, 46, 212, 5, 30, 147, 102, 164,
                154, 107, 170, 9, 93, 105, 219, 10, 199, 180, 59, 181, 76, 249, 228, 111, 253, 253,
                246, 246, 37, 49, 188, 30, 69, 99, 3, 178, 0, 241, 6, 157, 173, 19, 140, 49, 47,
                209, 94, 142, 220, 36, 87, 170, 78, 85, 128, 65, 123, 126, 151, 67, 224, 212, 4,
                158, 39, 40, 15, 69, 103, 39, 236, 187, 8, 227, 36, 118, 118, 36, 31, 12, 52, 71,
                250, 104, 6, 243, 193, 22, 59, 195, 222, 75, 218, 6,
            ],
            Protocol::Unknown => vec![
                69, 0, 0, 61, 92, 138, 64, 0, 64, 1, 170, 127, 0, 0, 1, 8, 8, 8, 8, 1, 144, 208, 0,
                53, 0, 41, 52, 13, 201, 243, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 99, 104, 97, 116, 6,
                104, 117, 98, 98, 108, 111, 3, 111, 114, 103, 0, 0, 1, 0, 1,
            ],
        }
    }

    fn ipv4_with_options() -> Vec<u8> {
        vec![
            70, 0, 0, 61, 92, 138, 64, 0, 64, 17, 170, 127, 0, 0, 1, 8, 8, 8, 8, 1, 144, 208, 0,
            53, 0, 41, 52, 13, 201, 243, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 99, 104, 97, 116, 6, 104,
            117, 98, 98, 108, 111, 3, 111, 114, 103, 0, 0, 1, 0, 1,
        ]
    }

    fn ipv6_packet_bytes(protocol: Protocol) -> Result<Vec<u8>, Box<dyn Error>> {
        let packet = match protocol {
            Protocol::Udp => Ok(vec![
                96, 0, 0, 61, 92, 138, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 7,
                209, 18, 252, 18, 252, 0, 0, 0, 0, 0, 0, 0, 0, 34, 184, 184, 99, 104, 97, 116, 6,
                104, 117, 98, 98, 108, 111, 3, 111, 114, 103, 0, 0, 1, 0, 1,
            ]),
            Protocol::Tcp => Ok(vec![
                96, 0, 0, 61, 92, 138, 6, 0, 64, 6, 170, 83, 10, 128, 31, 18, 10, 64, 0, 1, 144,
                208, 0, 53, 0, 41, 52, 13, 201, 243, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 99, 104, 97,
                116, 6, 104, 117, 98, 98, 108, 111, 3, 111, 114, 103, 0, 0, 1, 0, 1,
            ]),
            Protocol::Unknown => Err("Not an acknowledgable protocol"),
        };

        Ok(packet?)
    }

    fn ipv4_packet_tcp() -> IpPacket {
        IpPacket {
            version: IpVersion::Ipv4,
            protocol: Protocol::Tcp,
            source_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            data: ipv4_packet_bytes(Protocol::Tcp),
        }
    }

    fn ipv4_packet_udp() -> IpPacket {
        IpPacket {
            version: IpVersion::Ipv4,
            protocol: Protocol::Udp,
            source_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            data: ipv4_packet_bytes(Protocol::Udp),
        }
    }

    fn ipv4_packet_tcp_incoming() -> IpPacket {
        let data = vec![
            69, 0, 1, 72, 233, 36, 64, 0, 64, 6, 67, 142, 8, 8, 8, 8, 127, 0, 0, 1, 208, 234, 1,
            187, 247, 89, 28, 109, 222, 186, 190, 253, 128, 24, 95, 247, 14, 56, 0, 0, 1, 1, 8, 10,
            211, 48, 238, 16, 146, 224, 159, 152, 23, 3, 3, 1, 15, 36, 159, 112, 182, 7, 26, 40,
            78, 203, 40, 151, 146, 172, 45, 76, 156, 222, 103, 188, 89, 211, 164, 138, 175, 127,
            39, 183, 159, 3, 239, 194, 49, 100, 17, 178, 149, 0, 116, 121, 15, 15, 97, 213, 232,
            88, 73, 50, 243, 176, 251, 229, 143, 227, 108, 207, 30, 30, 160, 237, 133, 132, 80,
            177, 238, 32, 19, 16, 204, 111, 159, 130, 171, 81, 98, 216, 128, 206, 155, 146, 206,
            157, 112, 216, 70, 170, 66, 246, 171, 12, 234, 161, 177, 53, 78, 180, 237, 128, 128,
            210, 177, 76, 248, 183, 37, 218, 30, 188, 99, 190, 113, 13, 94, 29, 109, 206, 38, 7,
            119, 107, 62, 125, 60, 145, 96, 64, 144, 101, 104, 132, 67, 170, 243, 236, 37, 115, 40,
            24, 170, 103, 24, 113, 24, 228, 211, 39, 155, 211, 63, 173, 179, 112, 31, 143, 168,
            166, 122, 117, 12, 95, 7, 4, 33, 25, 192, 143, 249, 1, 18, 230, 163, 115, 224, 33, 169,
            39, 52, 70, 212, 46, 212, 5, 30, 147, 102, 164, 154, 107, 170, 9, 93, 105, 219, 10,
            199, 180, 59, 181, 76, 249, 228, 111, 253, 253, 246, 246, 37, 49, 188, 30, 69, 99, 3,
            178, 0, 241, 6, 157, 173, 19, 140, 49, 47, 209, 94, 142, 220, 36, 87, 170, 78, 85, 128,
            65, 123, 126, 151, 67, 224, 212, 4, 158, 39, 40, 15, 69, 103, 39, 236, 187, 8, 227, 36,
            118, 118, 36, 31, 12, 52, 71, 250, 104, 6, 243, 193, 22, 59, 195, 222, 75, 218, 6,
        ];
        IpPacket {
            version: IpVersion::Ipv4,
            protocol: Protocol::Tcp,
            destination_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            source_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            data,
        }
    }

    fn outgoing_socket() -> Socket {
        Socket {
            inode: 123,
            process_name: Some(String::from("firefox")),
            pid: Some(123),
            protocol: Some(Protocol::Tcp),
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            destination_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            source_port: Some(123),
            destination_port: Some(456),
            direction: Some(Direction::Outgoing),
            packets: vec![],
            app_packets_size: None,
        }
    }

    fn local_socket() -> Socket {
        Socket {
            inode: 123,
            process_name: Some(String::from("firefox")),
            pid: Some(123),
            protocol: Some(Protocol::Tcp),
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            destination_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            source_port: Some(123),
            destination_port: Some(456),
            direction: None,
            packets: vec![],
            app_packets_size: None,
        }
    }

    fn process() -> ProcessNetworkMetrics {
        ProcessNetworkMetrics {
            name: String::from("firefox"),
            pid: 123,
            sockets_inodes: Some(vec![37312, 37313]),
            total_received_bytes: 0,
            total_transmitted_bytes: 0,
        }
    }

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
            assert_eq!(&scaph_net_interface.ip_networks, interface.1.ip_networks())
        });
    }

    #[test]
    fn it_should_identify_an_ipv4_address_from_hexadecimal_notation() {
        let hex_string = "0100007F";

        let parsed_address = parse_address_from_hex(hex_string).unwrap();

        let expected_address = Ipv4Addr::new(127, 0, 0, 1);
        assert_eq!(parsed_address, expected_address);
    }

    #[test]
    fn it_should_identify_an_ipv6_address_from_hexadecimal_notation() {
        let hex_string = "00000000000000000000000001000000";

        let parsed_address = parse_address_from_hex(hex_string).unwrap();

        let expected_address = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 256, 0);
        assert_eq!(parsed_address, expected_address);
    }

    #[test]
    fn it_should_identify_a_port_from_hexadecimal_notation() {
        let hex_string = "0277";

        let parsed_port = parse_port_from_hex(hex_string).unwrap();

        let expected_port = 631;

        assert_eq!(parsed_port, expected_port);
    }

    #[test]
    fn it_should_identify_the_sockets_linked_to_a_network_interface() {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let tcp_sockets_fixture = Path::new(manifest_dir).join("tests/fixtures/tcp");
        let path = tcp_sockets_fixture.as_path();

        let ip_network = IpNetwork {
            addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            prefix: 0,
        };
        let ip_networks: Vec<IpNetwork> = vec![ip_network];
        let mut network_interface = NetworkInterface {
            name: String::from("enp1s0"),
            total_transmitted_bytes: 0,
            total_received_bytes: 0,
            ip_networks,
            sockets: vec![],
            packet_capture: None,
        };

        network_interface.identify_sockets(path);

        let expected_destination_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

        let network_sockets = network_interface.sockets;

        assert_eq!(network_sockets[0].source_ip, Some(ip_network.addr));
        assert_eq!(
            network_sockets[0].destination_ip,
            Some(expected_destination_ip)
        );
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
        let first_process = ProcessNetworkMetrics {
            name: String::from("firefox"),
            pid: 123,
            sockets_inodes: Some(vec![37312, 37313]),
            total_received_bytes: 0,
            total_transmitted_bytes: 0,
        };

        let second_process = ProcessNetworkMetrics {
            name: String::from("signal_desktop"),
            pid: 456,
            sockets_inodes: Some(vec![28907, 16344]),
            total_received_bytes: 0,
            total_transmitted_bytes: 0,
        };

        let mut socket = Socket::new(
            37312,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            631,
            0,
        );

        socket.identify_process(vec![&first_process, &second_process]);

        assert_eq!(socket.process_name.unwrap(), first_process.name);
        assert_eq!(socket.pid.unwrap(), first_process.pid);
    }

    #[test]
    fn it_should_identify_an_ipv4_packet() {
        let packet = ipv4_packet_bytes(Protocol::Udp);

        let parsed_packet = IpPacket::new(&packet).unwrap();

        assert_eq!(parsed_packet.version, IpVersion::Ipv4);
    }

    #[test]
    fn it_should_identify_an_ipv6_packet() {
        let packet = ipv6_packet_bytes(Protocol::Udp).unwrap();

        let parsed_packet = IpPacket::new(&packet).unwrap();

        assert_eq!(parsed_packet.version, IpVersion::Ipv6);
    }

    #[test]
    fn it_should_identify_the_udp_protocol_for_an_ip_packet() {
        let packet = ipv6_packet_bytes(Protocol::Udp).unwrap();

        let parsed_packet = IpPacket::new(&packet).unwrap();

        assert_eq!(parsed_packet.protocol, Protocol::Udp);
    }

    #[test]
    fn it_should_identify_the_tcp_protocol_for_an_ip_packet() {
        let packet = ipv6_packet_bytes(Protocol::Tcp).unwrap();

        let parsed_packet = IpPacket::new(&packet).unwrap();

        assert_eq!(parsed_packet.protocol, Protocol::Tcp);
    }

    #[test]
    fn it_should_identify_the_source_and_destination_addresses_for_an_ipv4_packet() {
        let packet = ipv4_packet_bytes(Protocol::Tcp);

        let parsed_packet = IpPacket::new(&packet).unwrap();

        assert_eq!(parsed_packet.source_ip, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(parsed_packet.destination_ip, Ipv4Addr::new(8, 8, 8, 8));
    }

    #[test]
    fn it_should_identify_the_source_and_destination_addresses_for_an_ipv6_packet() {
        let packet = ipv6_packet_bytes(Protocol::Udp).unwrap();

        let parsed_packet = IpPacket::new(&packet).unwrap();

        assert_eq!(
            parsed_packet.source_ip,
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)
        );
        assert_eq!(
            parsed_packet.destination_ip,
            Ipv6Addr::new(2001, 4860, 4860, 0, 0, 0, 0, 8888)
        );
    }

    #[test]
    fn it_should_not_generate_an_ip_packet_if_the_options_field_is_present() {
        let packet = ipv4_with_options();

        let maybe_ip_packet = IpPacket::new(&packet);

        assert!(maybe_ip_packet.is_err());
        assert_eq!(maybe_ip_packet.unwrap_err(), PacketError::OptionsFieldError)
    }

    #[test]
    fn it_should_generate_a_tcp_packet_when_the_correct_protocol_has_been_identified() {
        let ip_packet = ipv4_packet_tcp();
        let tcp_packet = TransportLayerPacket::new(&ip_packet).unwrap();

        assert_eq!(tcp_packet.protocol, Protocol::Tcp);
    }

    #[test]
    fn it_should_parse_a_tcp_packet_to_get_the_relevant_information() {
        let ip_packet = ipv4_packet_tcp();

        let mut tcp_packet = TransportLayerPacket::new(&ip_packet).unwrap();

        tcp_packet.parse();

        let source_addr = tcp_packet.source_address.unwrap();
        let dest_addr = tcp_packet.destination_address.unwrap();

        assert_eq!(source_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(source_addr.port(), 53482);
        assert_eq!(dest_addr.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(dest_addr.port(), 443);
        assert_eq!(tcp_packet.size, 308);
        assert_eq!(tcp_packet.data.len(), 308);
    }

    #[test]
    fn it_should_identify_the_application_packet_size_from_a_tcp_packet() {
        let ip_packet = ipv4_packet_tcp();
        let tcp_packet = TransportLayerPacket::new(&ip_packet).unwrap();

        let expected_size = ((tcp_packet.data.len() * 8) - 256) as u32;
        let identified_size = identify_app_packet_size(&tcp_packet.data, Protocol::Tcp);

        assert_eq!(identified_size, expected_size);
    }

    #[test]
    fn it_should_generate_an_udp_packet_when_the_correct_protocol_has_been_identified() {
        let ip_packet = ipv4_packet_udp();
        let udp_packet = TransportLayerPacket::new(&ip_packet).unwrap();

        assert_eq!(udp_packet.protocol, Protocol::Udp);
    }

    #[test]
    fn it_should_not_generate_a_transport_layer_packet_if_an_unmanaged_protocol_has_been_identified()
     {
        let data = ipv4_packet_bytes(Protocol::Unknown);
        let ip_packet = IpPacket::new(&data).unwrap();

        let maybe_transport_packet = TransportLayerPacket::new(&ip_packet);

        assert!(maybe_transport_packet.is_err());
        assert_eq!(
            maybe_transport_packet.unwrap_err(),
            PacketError::FilteredPacket
        );
    }

    #[test]
    fn it_should_parse_a_udp_packet_to_get_the_relevant_information() {
        let ip_packet = ipv4_packet_udp();

        let mut udp_packet = TransportLayerPacket::new(&ip_packet).unwrap();

        udp_packet.parse();

        let source_addr = udp_packet.source_address.unwrap();
        let dest_addr = udp_packet.destination_address.unwrap();

        let expected_size = ip_packet.data[20..].len();

        assert_eq!(source_addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(source_addr.port(), 37072);
        assert_eq!(dest_addr.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(dest_addr.port(), 53);
        assert_eq!(udp_packet.size, expected_size as u64);
        assert_eq!(udp_packet.data.len(), expected_size);
    }

    #[test]
    fn it_should_identify_the_application_packet_size_from_a_udp_packet() {
        let ip_packet = ipv4_packet_udp();
        let udp_packet = TransportLayerPacket::new(&ip_packet).unwrap();

        let expected_size = ((udp_packet.data.len() * 8) - 16) as u32;
        let identified_size = identify_app_packet_size(&udp_packet.data, Protocol::Udp);

        assert_eq!(identified_size, expected_size);
    }

    #[test]
    fn it_should_identify_if_a_packet_is_outgoing() {
        let ip_packet = ipv4_packet_udp();
        let udp_packet = TransportLayerPacket::new(&ip_packet).unwrap();

        let local_ips = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];

        let is_outgoing = get_direction(
            &udp_packet.source_ip,
            &udp_packet.destination_ip,
            &local_ips,
        );

        assert_eq!(is_outgoing, Direction::Outgoing);
    }

    #[test]
    fn it_should_identify_if_a_packet_is_incoming() {
        let data = vec![
            69, 0, 0, 61, 92, 138, 64, 0, 64, 17, 170, 8, 8, 8, 8, 127, 0, 0, 1, 1, 144, 208, 0,
            53, 0, 41, 52, 13, 201, 243, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 99, 104, 97, 116, 6, 104,
            117, 98, 98, 108, 111, 3, 111, 114, 103, 0, 0, 1, 0, 1,
        ];
        let ip_packet = IpPacket {
            version: IpVersion::Ipv4,
            protocol: Protocol::Tcp,
            source_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            destination_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            data,
        };
        let incoming_udp_packet = TransportLayerPacket::new(&ip_packet).unwrap();

        let local_ips = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];

        let is_incoming = get_direction(
            &incoming_udp_packet.source_ip,
            &incoming_udp_packet.destination_ip,
            &local_ips,
        );

        assert_eq!(is_incoming, Direction::Incoming);
    }

    #[test]
    fn it_should_assign_a_direction_to_a_socket() {
        let mut socket = Socket::new(
            123,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            123,
            456,
        );
        let local_ips = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];
        socket.set_direction(&local_ips);

        assert_eq!(socket.direction.unwrap(), Direction::Outgoing);
    }

    #[test]
    fn it_should_identify_a_local_socket() {
        let mut socket = local_socket();
        let local_ips = vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))];
        socket.set_direction(&local_ips);

        assert_eq!(socket.direction.unwrap(), Direction::Local);
    }

    #[test]
    fn it_should_estimate_the_packets_total_size_for_a_socket() {
        let mut socket = outgoing_socket();
        let ip_packet = ipv4_packet_tcp();
        let tcp_packet = TransportLayerPacket::new(&ip_packet).unwrap();
        let tcp_packets = vec![tcp_packet.clone(), tcp_packet.clone()];

        socket.packets = tcp_packets;
        socket.evaluate_packets_size();

        let expected_size = (((tcp_packet.data.len() * 8) - 256) * 2) as u64;

        assert_eq!(socket.app_packets_size.unwrap(), expected_size);
    }

    #[test]
    fn it_should_update_a_process_network_metrics_with_its_associated_sockets_traffic() {
        let mut process = process();

        let process_inodes = process.sockets_inodes.clone().unwrap();

        let first_socket = Socket {
            inode: process_inodes[0],
            process_name: Some(String::from("firefox")),
            pid: Some(process.pid),
            protocol: Some(Protocol::Tcp),
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            destination_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            source_port: Some(123),
            destination_port: Some(456),
            direction: Some(Direction::Outgoing),
            packets: vec![],
            app_packets_size: Some(1024),
        };

        let second_socket = Socket {
            inode: process_inodes[1],
            process_name: Some(String::from("firefox")),
            pid: Some(process.pid),
            protocol: Some(Protocol::Tcp),
            source_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            destination_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            source_port: Some(123),
            destination_port: Some(456),
            direction: Some(Direction::Incoming),
            packets: vec![],
            app_packets_size: Some(2056),
        };

        let sockets = vec![first_socket, second_socket];

        process.update_traffic(&sockets);

        assert_eq!(process.total_transmitted_bytes, 1024);
        assert_eq!(process.total_received_bytes, 2056);
    }

    #[test]
    fn it_should_identify_accordingly_a_captured_ethernet_frame_depending_on_the_data_link_type() {
        let ethernet_dlt = 1;
        let ethernet_frame = ethernet_frame();

        let packet = Packet::new(&ethernet_dlt, &ethernet_frame);
        let identified_type = packet.identify();

        let expected_type = PacketType::Ethernet;

        assert_eq!(identified_type, expected_type);
    }

    #[test]
    fn it_should_generate_an_ip_packet_after_identifying_an_ethernet_frame_and_getting_its_payload()
    {
        let ethernet_frame = ethernet_frame();
        let dlt = 1;
        let packet = Packet::new(&dlt, &ethernet_frame);

        let payload = packet.payload();

        let maybe_ip_packet = IpPacket::new(&payload);
        assert!(maybe_ip_packet.is_ok());
        assert_eq!(maybe_ip_packet.unwrap().protocol, Protocol::Udp);
    }

    #[test]
    fn it_should_generate_an_ip_packet_after_identifying_a_raw_ip_packet_and_getting_its_payload() {
        let raw_ip_packet = ipv4_packet_bytes(Protocol::Udp);
        let raw_ip_dlts = [12, 101, 228, 229];
        raw_ip_dlts.iter().for_each(|dlt| {
            let packet = Packet::new(dlt, &raw_ip_packet);

            let payload = packet.payload();

            let maybe_ip_packet = IpPacket::new(&payload);
            assert!(maybe_ip_packet.is_ok());
            assert_eq!(maybe_ip_packet.unwrap().protocol, Protocol::Udp);
        });
    }

    #[test]
    fn it_should_generate_an_ip_packet_after_distinguishing_an_ethernet_frame_and_a_vlan_tagged_ethernet_frame()
     {
        let ethernet_frame = ethernet_frame_vlan_tagged();
        let dlt = 1;
        let packet = Packet::new(&dlt, &ethernet_frame);

        let payload = packet.payload();

        let maybe_ip_packet = IpPacket::new(&payload);
        assert!(maybe_ip_packet.is_ok());
        assert_eq!(maybe_ip_packet.unwrap().protocol, Protocol::Udp);
    }

    #[test]
    fn it_should_filter_packets_received_by_a_socket_to_only_keep_those_related_to_this_socket() {
        let mut socket = outgoing_socket();

        let packets: Vec<IpPacket> = vec![
            ipv4_packet_tcp(),
            ipv4_packet_tcp(),
            ipv4_packet_tcp_incoming(),
        ];

        packets.iter().for_each(|packet| {
            socket.filter_packet(packet);
        });

        assert_eq!(socket.packets.len(), 2);
    }
}
