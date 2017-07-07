#!/usr/bin/python

DOCUMENTATION = '''
---
module: cisco_asa_acl
short_description: Creates Access Lists on Cisco ASA
'''

EXAMPLES = '''
- name: Create access list
  cisco_asa_acl:
    ip: "10.10.10.10"
    username: admin
    password: Password_1
    secret: Password_2
    lists:
      - access-list extended extended permit tcp any any eq 8888
      - access-list test_ASA extended permit tcp any any eq 8888
'''

from ansible.module_utils.basic import *
from netmiko import ConnectHandler

def execute_acl(data):
    params = data.copy()
    del params['lists']

    has_changed = 0
    has_not_changed = 0

    connect = ConnectHandler(**params)
    acl_config = connect.send_command('show running-config access-list')
    connect.config_mode()

    for acl in data['lists']:
        if acl not in acl_config:
            command = connect.send_command(acl)
            regex = re.search('(error|warning)', command, re.IGNORECASE)
            if regex:
                return True, True, {"status": command}
            has_changed += 1
        else:
            has_not_changed += 1

    if has_changed > 0:
        return False, True, {"status": "Has changed some ASL(s)"}
    elif (has_not_changed > 0 and has_not_changed == len(data['lists'])
            and has_changed == 0):
        return False, False, {"status": "ACL(s) already exist"}
    else:
        return True, True, {"status": "Something went really wrong" +
               " " + "you should have never see this message"}

def main():
    fields = {
        "device_type": {"default": "cisco_asa", "type": "str"},
        "ip": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": True, "type": "str", "no_log": True},
        "secret": {"required": False, "type": "str", "no_log": True},
        "lists": {"required": True, "type": "list"}
    }

    module = AnsibleModule(argument_spec=fields)
    is_error, has_changed, result =  execute_acl(module.params)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg=result)
if __name__ == '__main__':
    main()