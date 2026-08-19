import unittest
from unittest.mock import Mock
from keeper_secrets_manager_core.dto.dtos import KeeperFolder
from keeper_secrets_manager_cli.folder import Folder
from conftest import KSMTestCase


def _make_folder(uid, parent_uid='', key=b'\x00' * 32):
    return KeeperFolder(folder_key=key, folder_uid=uid, parent_uid=parent_uid, name=uid)


def _make_cli(folders):
    cli = Mock()
    cli.client.get_folders.return_value = folders
    return cli


class BuildFolderOptionsTest(KSMTestCase):

    def test_root_no_parent(self):
        # NSF root has no parent_uid; CreateOptions should reference root as shared folder.
        root = _make_folder('ROOT')
        opts, _ = Folder(cli=_make_cli([root])).build_folder_options('ROOT')
        self.assertEqual(opts.folder_uid, 'ROOT')
        self.assertEqual(opts.subfolder_uid, 'ROOT')

    def test_subfolder_walks_to_root(self):
        # Passing a one-level-deep subfolder UID; walk should stop at root.
        root = _make_folder('ROOT')
        sub = _make_folder('SUB', parent_uid='ROOT')
        opts, _ = Folder(cli=_make_cli([root, sub])).build_folder_options('SUB')
        self.assertEqual(opts.folder_uid, 'ROOT')
        self.assertEqual(opts.subfolder_uid, 'SUB')

    def test_three_level_walk(self):
        # LEAF -> MID -> ROOT; walk must reach ROOT regardless of depth.
        root = _make_folder('ROOT')
        mid = _make_folder('MID', parent_uid='ROOT')
        leaf = _make_folder('LEAF', parent_uid='MID')
        opts, _ = Folder(cli=_make_cli([root, mid, leaf])).build_folder_options('LEAF')
        self.assertEqual(opts.folder_uid, 'ROOT')
        self.assertEqual(opts.subfolder_uid, 'LEAF')

    def test_parent_outside_grant_stops_at_effective_root(self):
        # NSF root has a parent_uid pointing to a folder NOT in the app's grant.
        # The walk must terminate at the NSF root (the lowest folder whose parent
        # is outside the grant) rather than looping forever.
        nsf_root = _make_folder('NSF_ROOT', parent_uid='DRIVE_CONTAINER')
        opts, _ = Folder(cli=_make_cli([nsf_root])).build_folder_options('NSF_ROOT')
        self.assertEqual(opts.folder_uid, 'NSF_ROOT')
        self.assertEqual(opts.subfolder_uid, 'NSF_ROOT')


if __name__ == '__main__':
    unittest.main()
