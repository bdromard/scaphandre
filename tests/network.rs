use scaphandre::sensors::network::{ProcessNetworkMetrics, identify_psock_inodes};
mod common;

#[test]
fn it_should_identify_the_sockets_and_their_inodes_among_file_descriptors_for_a_process() {
    common::setup_fs_proc();
    let tmp_dir = common::tmp_tests_dir();

    let mut process = ProcessNetworkMetrics::new("firefox", 123_u32, 0, 0);

    let expected_inodes = vec![12345, 67890];

    process.identify_psock_inodes(&tmp_dir);

    assert_eq!(process.sockets_inodes.unwrap(), expected_inodes);
}
