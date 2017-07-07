#!/usr/bin/python

from ansible.module_utils.basic import *
from netmiko import ConnectHandler

def execute_acl(data):
    params = data.copy()
    del params['lines']

    has_changed = 0
    has_not_changed = 0

    connect = ConnectHandler(**params)
    acl_config = connect.send_connect('show running-config access-list')
    connect.config_mode()

    for acl in data['lines']:
        if acl not in acl_config:
            connect.send_connect(acl)
            has_changed += 1
        else:
            has_not_changed += 1

    if has_changed > 0:
        return False, True, {"status": "Has changed some ASL(s)"}
    elif (has_not_changed > 0 and has_not_changed == len(data['lines'])
            and has_changed == 0):
        return False, False, {"status": "ACL(s) already exist"}
    else:
        return True, True, {"status": "Has changed some ASL(s)"}

def main():
    fields = {
        "device_type": {"default": "cisco_asa", "type": "str"},
        "ip": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": True, "type": "str"},
        "secret": {"required": False, "type": "str"},
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