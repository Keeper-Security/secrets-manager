#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from ansible.plugins.action.copy import ActionModule as ActionBase
from ansible.errors import AnsibleError
from keeper_secrets_manager_ansible import KeeperAnsible
from ansible.utils.display import Display

DOCUMENTATION = r'''
---
module: keeper_copy

short_description: Copy a Keeper vault secret to the remote server.

version_added: "1.0.0"

description:
    - Copy a file or value from the Keeper Vault to the remote server.
    - Can use Keeper notation or separate uid, field type, and file/field to specify the record.
    - Has the same options at the normal Ansible copy module.
author:
    - John Walstra
options:
  uid:
    description:
    - The UID of the Keeper Vault record.
    type: str
    required: no
  field:
    description:
    - The label, or type, of the standard field in record that contains the value.
    - If the value has a complex value, use notation to get the specific value from the complex value.
    type: str
    required: no
  custom_field:
    description:
    - The label, or type, of the user added customer field in record that contains the value.
    - If the value has a complex value, use notation to get the specific value from the complex value.
    type: str
    required: no
  file:
    description:
    - The file name of the file that contains the value.
    type: str
    required: no
  notation:
    description:
    - The Keeper notation to access record that contains the value.
    - Use notation when you want a specific value.
    - See https://docs.keeper.io/secrets-manager/secrets-manager/about/keeper-notation for more information/
    type: str
    required: no
    version_added: '1.0.1'  
  dest:
    description:
    - Remote absolute path where the file should be copied to.
    - If C(src) is a directory, this must be a directory too.
    - If C(dest) is a non-existent path and if either C(dest) ends with "/" or C(src) is a directory, C(dest) is created.
    - If I(dest) is a relative path, the starting directory is determined by the remote host.
    - If C(src) and C(dest) are files, the parent directory of C(dest) is not created and the task fails if it does not already exist.
    type: path
    required: yes
  backup:
    description:
    - Create a backup file including the timestamp information so you can get the original file back if you somehow clobbered it incorrectly.
    type: bool
    default: no
  force:
    description:
    - Influence whether the remote file must always be replaced.
    - If C(yes), the remote file will be replaced when contents are different than the source.
    - If C(no), the file will only be transferred if the destination does not exist.
    - Alias C(thirsty) has been deprecated and will be removed in 2.13.
    type: bool
    default: yes
    aliases: [ thirsty ]
  mode:
    description:
    - The permissions of the destination file or directory.
    - For those used to C(/usr/bin/chmod) remember that modes are actually octal numbers.
      You must either add a leading zero so that Ansible's YAML parser knows it is an octal number
      (like C(0644) or C(01777)) or quote it (like C('644') or C('1777')) so Ansible receives a string
      and can do its own conversion from string into number. Giving Ansible a number without following
      one of these rules will end up with a decimal number which will have unexpected results.
    - As of Ansible 1.8, the mode may be specified as a symbolic mode (for example, C(u+rwx) or C(u=rw,g=r,o=r)).
    - As of Ansible 2.3, the mode may also be the special string C(preserve).
    - C(preserve) means that the file will be given the same permissions as the source file.
    - When doing a recursive copy, see also C(directory_mode).
    - If C(mode) is not specified and the destination file B(does not) exist, the default C(umask) on the system will be used
      when setting the mode for the newly created file.
    - If C(mode) is not specified and the destination file B(does) exist, the mode of the existing file will be used.
    - Specifying C(mode) is the best way to ensure files are created with the correct permissions.
      See CVE-2020-1736 for further details.
  directory_mode:
    description:
    - When doing a recursive copy set the mode for the directories.
    - If this is not set we will use the system defaults.
    - The mode is only set on directories which are newly created, and will not affect those that already existed.
    type: raw
  follow:
    description:
    - This flag indicates that filesystem links in the destination, if they exist, should be followed.
    type: bool
    default: no
  local_follow:
    description:
    - This flag indicates that filesystem links in the source tree, if they exist, should be followed.
    type: bool
    default: yes
  checksum:
    description:
    - SHA1 checksum of the file being transferred.
    - Used to validate that the copy of the file was successful.
    - If this is not provided, ansible will use the local calculated checksum of the src file.
    type: str
'''

EXAMPLES = r'''
- name: Copy SSL certificate
  keeper_copy:
    uid: XXX
    file: example.crt
    dest: /etc/ssl
    mode: "0600"
    owner: root
    group: root
- name: Copy SSL certificate via Notation
  keeper_copy:
    notation: XXX/file/example.crt
    dest: /etc/ssl
    mode: "0600"
    owner: root
    group: root
- name: Copy SSH Keys
  keeper_copy:
    notation: "XXX/field/keyPair[{{ item.notation_key }}]"
    dest: "/home/my_user/.ssh/{{ item.filename }}"
    mode: "0600"
    owner: my_user
    group: staff
  loop:
    - { notation_key: "privateKey", filename: "id_rsa" }
    - { notation_key: "publicKey",  filename: "id_rsa.pub" }
'''

RETURN = r'''
dest:
    description: Destination file/path.
    returned: success
    type: str
    sample: /path/to/file.txt
md5sum:
    description: MD5 checksum of the file after running copy.
    returned: when supported
    type: str
    sample: 2a5aeecc61dc98c4d780b14b330e3282
checksum:
    description: SHA1 checksum of the file after running copy.
    returned: success
    type: str
    sample: 6e642bb8dd5c2e027bf21dd923337cbb4214f827
backup_file:
    description: Name of backup file created.
    returned: changed and if backup=yes
    type: str
    sample: /path/to/file.txt.2015-02-12@22:09~
gid:
    description: Group id of the file, after execution.
    returned: success
    type: int
    sample: 100
group:
    description: Group of the file, after execution.
    returned: success
    type: str
    sample: httpd
owner:
    description: Owner of the file, after execution.
    returned: success
    type: str
    sample: httpd
uid:
    description: Owner id of the file, after execution.
    returned: success
    type: int
    sample: 100
mode:
    description: Permissions of the target, after execution.
    returned: success
    type: str
    sample: 0644
size:
    description: Size of the target, after execution.
    returned: success
    type: int
    sample: 1220
state:
    description: State of the target, after execution.
    returned: success
    type: str
    sample: file
'''

display = Display()


class ActionModule(ActionBase):

    def run(self, tmp=None, task_vars=None):

        if task_vars is None:
            task_vars = {}

        keeper = KeeperAnsible(task_vars=task_vars)

        if self._task.args.get("notation") is not None:
            value = keeper.get_value_via_notation(self._task.args.get("notation"))
        else:
            uid = self._task.args.pop("uid", None)
            if uid is None:
                raise AnsibleError("The uid is blank. keeper_copy requires this value to be set.")

            # Try to get either the field, custom_field, or file name.
            field_type_enum, field_key = keeper.get_field_type_enum_and_key(args=self._task.args)

            value = keeper.get_value(uid, field_type=field_type_enum, key=field_key)

        # Make sure 'src' is not set. We are going to use 'content' instead.
        self._task.args.pop("src", None)
        self._task.args.pop("remote_src", None)

        # The built-in copy module won't like these, remove them.
        self._task.args.pop("field", None)
        self._task.args.pop("file", None)
        self._task.args.pop("custom_field", None)
        self._task.args.pop("notation", None)

        # Add the file content
        self._task.args["content"] = value

        # Call Ansible built-in copy
        result = super(ActionModule, self).run(tmp, task_vars)

        # Attempt to add back the keeper values for debug purposes.
        if type(result) is dict:
            invocation = result.get("invocation")
            if invocation is not None:
                module_args = invocation.get("module_args")
                if module_args is not None:
                    # Remove the src and content, if they exists, since they are not part of this
                    # plugin. Also they could leak values.
                    module_args.pop('src', None)
                    module_args.pop('content', None)

            result = keeper.add_secret_values_to_results(result)

        return result
