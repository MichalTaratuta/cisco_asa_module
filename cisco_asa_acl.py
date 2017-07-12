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
      - no access-list Left-to-Right extended permit ip host 172.16.1.110 host 192.168.1.110
      - access-list Left-to-Right extended permit tcp any any eq 8888
'''

from ansible.module_utils.basic import *
from netmiko import ConnectHandler

def parse_acl_name(module):
    first_line = True
    for line in module.params['lists']:
        ace = line.split()
        no_acl = ace[0] + ' ' + ace[1]

        if ace[0] != 'access-list' and no_acl != 'no access-list':
            module.fail_json(msg='All lines/commands must begin with "access-list" or "no access list"%s is not permitted' % ace[0])

        if len(ace) <= 1:
            module.fail_json(msg='All lines/commands must contain the name of the access-list')

        if first_line and ace[0] == 'no':
            acl_name = ace[2]
        elif first_line and ace[0] == 'access-list':
            acl_name = ace[1]
        else:
            if acl_name != ace[1]:
                module.fail_json(msg='All lines/commands must use the same access-list %s is not %s' % (ace[1], acl_name))
        first_line = False

def execute_acl(module):
    data = module.params.copy()

    del data['lists']

    connect = ConnectHandler(**data)
    acl_config = connect.send_command('show running-config access-list')
    connect.config_mode()

    has_changed = 0
    has_not_changed = 0

    for acl in module.params['lists']:
        cmd = connect.send_command(acl)
        regex = re.search('(error|warning)', cmd, re.IGNORECASE)

        ace = acl.split()

        if  ace[0] == 'no':
            del ace[0]
            no_acl = ' ' . join(ace)

            if no_acl in acl_config:
                if regex:
                    result = {"Status": "Something went wrong with this ACL:" +
                            + " " + str(acl)}
                    module.fail_json(msg=result)
                has_changed += 1
            else:
                has_not_changed += 1

        elif ace[0] == 'access-list':
            if acl not in acl_config:
                if regex:
                    result = {"Status": "Something went wrong with this ACL:" +
                            + " " + str(acl)}
                    module.fail_json(msg=result)
                has_changed += 1
            else:
                has_not_changed += 1

    if has_changed > 0:
        connect.send_command('write memory')
        result = {"status": "Changed some access-lists(s)," +
                        " " + "running-config saved"}
        module.exit_json(changed=has_changed, meta=result)
    elif (has_not_changed > 0 and has_not_changed == len(module.params['lists'])
            and has_changed == 0):
        result = {"status": "Nothing to change"}
        module.exit_json(changed=False, meta=result)
    else:
        result = {"status": "Something went really wrong" +
                       " " + "running-config has not been saved",
                       "cmd": acl}
        module.fail_json(msg=result)

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

    parse_acl_name(module)
    execute_acl(module)

if __name__ == '__main__':
    main()