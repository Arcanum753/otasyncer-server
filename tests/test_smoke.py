import smoke_test


def test_backup_restore_and_fs_update_flow():
    """Полный серверный цикл на fake-device: snapshot -> restore -> fs_update."""
    smoke_test.main()
