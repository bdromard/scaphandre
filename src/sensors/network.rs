use std::{
    fs::{read_to_string},
    path::{Path, PathBuf},
};

use sysinfo::NetworkData;

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
}
