use scaphandre::sensors::network::{ProcessNetworkMetrics};
use sysinfo::Pid;
mod common;

#[test]
fn it_should_identify_the_sockets_and_their_inodes_among_file_descriptors_for_a_process() {
    common::setup_fs_proc();
    let tmp_dir = common::tmp_tests_dir();

    let process = ProcessNetworkMetrics::new("firefox", &Pid::from_u32(123), &tmp_dir);

    let expected_inodes = vec![12345, 67890];

    assert_eq!(process.sockets_inodes.unwrap(), expected_inodes);
}
