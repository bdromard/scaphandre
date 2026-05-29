use scaphandre::sensors::network::{identify_psock_inodes};
mod common;

#[test]
fn it_should_identify_the_sockets_and_their_inodes_among_file_descriptors_for_a_process() {
    common::setup_fs_proc();
    let tmp_dir = common::tmp_tests_dir();

    let expected_inodes = [12345, 67890];

    let identified_inodes = identify_psock_inodes(123, &tmp_dir);

    assert_eq!(identified_inodes, expected_inodes);
}
