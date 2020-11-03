from ttp import ttp
from jinja2 import Environment, FileSystemLoader
import re
from pathlib import Path
from collections import defaultdict
from ipaddress import ip_address, ip_network
from copy import deepcopy
import argparse as argparse

def assemble(template_dir, data, config_file, templates):

    file_loader = FileSystemLoader(template_dir)
    env = Environment(loader=file_loader, trim_blocks=True, extensions=['jinja2.ext.do'])

    f = open(config_file, "w")
    for template in templates:
        cfg_template = env.get_template(template)
        cfg = cfg_template.render(data=data)
        f.write(cfg)
    f.close()

### TTP Macro
def build_list(data):
    if "\" \"" in data:
        t = data.split("\" \"")
        for i in range(0, len(t)):
            t[i] = t[i].strip("\"").replace(" ", "_")
            i+=1
        return t
    else:
        return [data.strip("\"").replace(" ", "_")]

### TTP Macro
def clean_str(data):
    return data.replace("\"","").replace(" ", "_")

### TTP Macro
def match_ip_or_any(data):
    import ipaddress
    if data == "any":
        return data
    elif "/" in data:
        return str(data)
    else:
        t = data.replace(" ", "/")
        return str(ipaddress.IPv4Network(t, strict=False))

### TTP Macro
def ignore_empty(data):
    if data == "\'\'":
        return bool(False)
    else:
        return data

### TTP Macro
def skip_empty(data):
    if data == {}:
        return False
    return data

def parse_config(input_file, ttp_template_dir):

    ### TTP Variable definitions
    vars = {
        "clean_phrase": [
            'ORPHRASE',
            'macro("clean_str")'
        ],
        "clean_list": [
            'ORPHRASE',
            'macro("build_list")'
        ]
    }

    cfg_input = Path(input_file).read_text()

    parser = ttp()
    # Note:
    #   - must add macros first, then vars and then you can add the template
    #   - if you add templates individually, you will get multiple entries in
    #       parser.result(). That is why it is easier to concatenate the
    #       individual template files and then just add them as a single template
    #       this way you get a results object for the entire fortinet config
    #       as opposed to one object per template file
    #
    # to get additional debug information from ttp
    # import logging
    # logging.basicConfig(level=logging.DEBUG)
    #


    parser.add_function(build_list, scope='macro')
    parser.add_function(clean_str, scope='macro')
    parser.add_function(skip_empty, scope='macro')
    parser.add_function(ignore_empty, scope="macro")
    parser.add_function(match_ip_or_any, scope="macro")
    parser.add_vars(vars)
    template = ""

    for t_file in Path(ttp_template_dir).iterdir():
        if t_file.is_file():
            template += "\n" + t_file.read_text()

    parser.add_template(template)
    parser.add_input(cfg_input)
    parser.parse()
    res = parser.result()[0][0]

    return res

def convert_config(res, output_file, j2_template_dir, rt_type):


    router_conf = dict()

    # address and address groups don't require any manipulation
    # hostname and dns servers are simple key mapping
    router_conf.update(
        {
            'addresses': res['fw_address']['addresses'],
            'address_groups': res['fw_address_group']['addrgrps'],
            'hostname': res['system']['hostname'],
            'dns': [res['dns']['primary'], res['dns']['secondary']]
        }
    )


    # interfaces will require mapping from fortinet interfaces to SRX interfaces
    #   - need to create a map of input vs output interface names
    #   - need to build interfaces structures as below
    #
    #data:
    #    ports:
    #        - name: xe-0/0/1
    #          primary_ip: 1.1.1.1/31
    #        - name: xe-0/0/2
    #          portchannel: reth0
    #        - name: xe-0/0/3
    #    portchannel:
    #        - name: reth0
    #          id: 0
    #          description: reth0
    #          primary_ip: 2.1.1.1/31
    #    sub_interfaces:
    #        - vlan_id: 75
    #          parent: xe-0/0/3
    #          primary_ip: 3.1.1.1/24
    #    loopback:
    #        primary_ip: 10.1.1.1/32
    #    portchannel_count: 1


    ####
    # interface structure creation
    #
    # need to translate `portN` to `xe-0/0/N`
    # need to translate `VlanX` , 'vlanX` to `xe-0/0/N unit X`
    # need to translate `port-channel-N` to `rethA` unit 0`
    # not supported in this code, but the vlan interface could be under the the port-channel
    #
    new_interfaces = defaultdict(list)
    intf_map = defaultdict(dict)
    agg_intf_count = 0

    interfaces = res['fw_interfaces']['interfaces']

    for item in interfaces:
        if item['type'] == 'physical':
            t = re.search("^port(\d+)$", item['name'])
            if t:
                port = t.group(1)
                new_intf = f"xe-0/0/{port}"
                unit = 0
                intf_map.update({ item['name']:
                                { 'name': new_intf,
                                  'unit': unit,
                                  'ip': item.get('ip', '0.0.0.0/0')
                                }
                            })
                tn = { "name": new_intf }
                if 'ip' in item.keys() and item['ip'] != '0.0.0.0/0':
                    tn.update({'primary_ip': item['ip']})
                tn.update({'description': item['description']})
                new_interfaces['ports'].append(tn)

        if item['type'] == 'vlan':
            t = re.search("^[v|V]lan(\d+)$", item['name'])
            if t:
                unit = item['access_vlan']
                tn = {"vlan_id": unit}
                if "parent_interface" in item.keys():
                    parent = intf_map[item['parent_interface'][0]]['name']
                    tn.update({"parent": parent})
                    intf_map.update({item['name']:
                                         {'name': parent,
                                          'unit': unit,
                                          'ip': item.get('ip', '0.0.0.0/0')
                                          }
                                     })
                if 'ip' in item.keys() and item['ip'] != '0.0.0.0/0':
                    tn.update({'primary_ip': item['ip']})
                tn.update({'description': item['description']})
                new_interfaces['sub_interfaces'].append(tn)

        if item['type'] == 'aggregate':
            t = re.search("^port-channel-(\d+)$", item['name'])
            if t:
                members = item['port_channel_members']
                reth_num = agg_intf_count
                new_intf = f"reth{reth_num}"
                tn = {"name": new_intf, 'id': reth_num}

                intf_map.update({item['name']:
                                     {'name': new_intf,
                                      'unit': 0,
                                      'ip': item.get('ip', '0.0.0.0/0')
                                      }
                                 })
                for member in members:
                    count = 0
                    new_member = intf_map[member]['name']
                    for t_intf in new_interfaces['ports']:
                        if t_intf['name'] == new_member:
                            new_interfaces['ports'][count].update({'portchannel': new_intf})
                        count+=1
                if 'ip' in item.keys() and item['ip'] != '0.0.0.0/0':
                    tn.update({'primary_ip': item['ip']})
                tn.update({'description': item['description']})
                new_interfaces['portchannels'].append(tn)
                agg_intf_count +=1

    new_interfaces['portchannel_count'] = agg_intf_count

    router_conf.update( {'interfaces' : dict(new_interfaces)} )

    ####
    # zone structure creation
    #
    # zones will require some logic
    #   - don't have to use zones in Fortinet, can just use list of interfaces
    #   - so need to determine if zones are being used or not and if not, create them
    #   - but native fortinet interfaces won't work, so need to translate those interfaces into SRX interface names first
    #   - zones struct should look as below
    # todo: determine if the interface names in the zone policies are sorted or ordered at time of entry
    #   - if sorted, then the logic implemented is fine. if not, then will need to sort the entries and then
    #     create the zone map
    #
    #data:
    #    zones:
    #        - name: IN
    #          interfaces:
    #            - xe-0/0/0.75
    #            - xe-0/0/0.76
    #        - name: OUT
    #          interfaces:
    #            - reth0.0
    #            - reth1.0
    new_zones = []
    zone_count = 0 # zones are just going to be named zone0, zone1, etc...
    zone_map = dict() # need this map when parsing the `fw_policy.rules`

    # if zones are defined, the TTP template parses them into the correct format
    # so just need to map that to the new structure
    # todo: code elsewhere looks for the zone_map dict, which won't exist if
    #   zones are natively created. need to address this
    if 'fw_zones' in res.keys():
        router_conf.update( {'zones': res['fw_zones']})
    else:
        # need to read through the fw_rules and identify all possible zones
        create_zone = set()
        for rule in res['fw_policy']['rules']:
            #skipping rules that are disabled
            if rule['status'] == 'enable':
                create_zone.add("::".join(rule['in_zone']))
                create_zone.add("::".join(rule['out_zone']))
                # but just joining the interfaces and putting them in a set I can easily find
                # the number of unique interface combinations that need to be converted to zones

        for item in create_zone:
            interfaces = item.split("::")
            mapped_intf = []
            # need to retrieve the new interface name, so looking through the intf_map dict
            for intf in interfaces:
                t = f"{intf_map[intf]['name']}.{intf_map[intf]['unit']}"
                mapped_intf.append(t)
            zone_name = f"zone{zone_count}"
            new_zones.append(
                {"name": zone_name,
                 "interfaces": mapped_intf}
            )
            zone_map[item] = zone_name
            zone_count+=1
        router_conf.update( {'zones': new_zones})


    ###
    # application and application groups
    # output should follow the format below:
    #
    #data:
    #    applications:
    #        - name: DNS
    #          terms:
    #            - name: t1
    #              protocol: tcp
    #              dport: 53
    #            - name: t2
    #              protocol: udp
    #              dport: 53
    #        - name: ICMP-ALL
    #          terms:
    #            - name: t1
    #              protocol: icmp
    #        - name: WEB
    #          terms:
    #            - name: t1
    #              protocol: tcp
    #              dport: 80
    #            - name: t2
    #              protocol: tcp
    #              dport: 443
    #        - name: MAIL
    #          terms:
    #            - name: t1
    #              protocol: tcp
    #              dport: 25
    #        - name: TELNET
    #          terms:
    #            - name: t1
    #              protocol: tcp
    #              dport: 23
    #    application-sets:
    #        - name: REQUIRED
    #          applications:
    #            - DNS
    #            - ICMP-ALL
    #            - WEB
    #            - MAIL
    #        - name: DENY
    #          applications:
    #            - TELNET

    # tackling application-sets first, since mapping will be simple

    app_sets = []

    for app_grp in res['fw_service_groups']['app_groups']:
        app_set = {
            "name": app_grp['app_group'],
            "applications": app_grp['apps']
        }
        app_sets.append(app_set)

    router_conf.update( {"application-sets": app_sets})

    # applications
    # things to keep in mind:
    #   - app can have udp and tcp port ranges
    #   - udp and tcp port ranges can be a list of ports and port-ranges
    #   - udp and tcp port ranges can specify src and dst ports and port-ranges
    #       - src port cannot be set alone, must be set in conjunction with dst port
    #       - format of this is 'dstPort:srcPort' where either can be a range
    #       - example if tcp_range is '513:512-1023' that means TCP dstPort = 513, srcPort = 512-1023
    # todo: figure out what to do with tcp_range=['0']. Currently setting protocol to TCP and dst port to 0
    # todo: figure out what to do with tcp_range=['0-65535:0-65535'] and protocol='ALL'.
    #       Currently setting protocol to TCP and full src and dst port range
    # todo: figure out what to do with protocol = IP and protocol_num = '0'. Currently just setting protocol to 0 in rule

    apps = []

    for app in res['fw_service_custom']['svc_name']:
        new_app = defaultdict(list)
        term_count = 0
        term_list = []
        new_term = {}
        # handle non tcp or udp apps
        if app['protocol'] == 'IP':
            new_term = {
                'name': f"term{term_count}",
                'protocol': app['protocol_num'] # if protocol is IP, there will always be a protocol number
            }
            # not sure what is required on SRX to provide same behavior, but just setting ip protocol to 0 for now
            # could optimize the code and get rid of this if statement, but keeping it here as a reminder
            # that this specific scenario may not be correctly handlded.
            if app['protocol_num'] == '0':
                new_term.update({'protocol': 0})
            term_list.append(new_term)
        elif app['protocol'] == 'ICMP': # handle ICMP, ignoring ICMP6
            new_term = {
                'name': f"term{term_count}",
                'protocol': 'icmp'
            }
            if 'icmp_type' in app.keys():
                new_term.update({'icmp_type': app['icmp_type']})
            if 'icmp_code' in app.keys():
                new_term.update({'icmp_code': app['icmp_code']})
            term_list.append(new_term)
        # handle apps with tcp ports
        if 'tcp_range' in app.keys():
            for tcp_port in app['tcp_range']:
                if ":" in tcp_port: # if format is A:B, A is dstPort, B is srcPort
                    dst_port, src_port = tcp_port.split(":")
                else:
                    dst_port = tcp_port
                    src_port = ""
                new_term = {
                    'name': f"term{term_count}",
                    'protocol': 'tcp',
                    'dport': dst_port
                }
                if src_port != "":
                    new_term.update({'sport': src_port})
                term_count +=1
                term_list.append(new_term)
        # handle apps with udp ports
        if 'udp_range' in app.keys():
            for udp_port in app['udp_range']:
                if ":" in udp_port:
                    dst_port, src_port = udp_port.split(":")
                else:
                    dst_port = udp_port
                    src_port = ""
                new_term = {
                    'name': f"term{term_count}",
                    'protocol': 'udp',
                    'dport': dst_port
                }
                if src_port != "":
                    new_term.update({'sport': src_port})
                term_count +=1
                term_list.append(new_term)
        new_app = {
            "name": app['name'],
            "terms": term_list
        }
        apps.append(new_app)

    router_conf.update( {"applications": apps})

    ###
    # source nat pools
    #
    # todo: determine if you can specify a prefix in fortigate pool definition or just ip-range
    # note: assuming for now that a prefix 1.1.1.1/24 is not valid input and it would need to
    #       be entered as 1.1.1.0 to 1.1.1.255
    # todo: determine if srx can handle a pool that is 1.1.1.1/32 as a range of 1.1.1.1 to 1.1.1.1
    # todo: determine if we need to handle the associated interfaces config for the ip pool
    # sample input
    # data:
    #     src_nat_pools:
    #     - name: pool1
    #       start_ip: 1.1.1.1
    #       end_ip: 1.1.1.10
    #     - name: pool2
    #       prefix: 10.1.1.0/24
    #

    src_nat_pools = []

    for pool in res['nat']['pools']:
        new_pool = dict()
        new_pool['name'] = pool['name']
        new_pool['start_ip'] = pool['start_ip']
        new_pool['end_ip'] = pool['end_ip']
        src_nat_pools.append(new_pool)

    router_conf.update({'src_nat_pools': src_nat_pools})


    ###
    # destination nat pools
    #
    # note: assumes that the mapping is 1:1
    # - mapped_ip is currently a list, so just using first element of the list
    #   should either properly handle multiple mapped IP or extract it with TTP as a singleton
    # todo: determine if we should switch this over to static nat instead of destination nat
    # sample input
    # data:
    #     dst_nat_pools:
    #     - name: pool1
    #       ext_ip: 1.1.1.1
    #       mapped_ip: 1.1.1.10
    #

    # data:
    #     addresses:
    #         - name: BAR
    #           type: ipmask
    #           ip: 10.1.1.0/24

    dst_nat_pools = []
    vip_address_book = [] # this will be the addresbook for the private ips of each VIP
    vip_name_list = []
    # creating this list so we can easily match fw rules that match a VIP and replace with the private IP address

    for pool in res['vips']['vip']:
        if pool['type'] == 'static-nat':
            priv_vip_addr = { # create address book entry for the private IP of the VIP (aka DNAT)
                "name": f"{pool['name']}-PRIV",
                "type": "ipmask",
                "ip": f"{pool['mapped_ip'][0]}/32"
            }
            pub_vip_addr = { # create address book entry for the public IP of the VIP (aka DNAT)
                "name": f"{pool['name']}",
                "type": "ipmask",
                "ip": f"{pool['ext_ip']}/32"
            }
            new_pool = dict()
            new_pool['name'] = pool['name']
            new_pool['mapped_ip'] = pool['mapped_ip'][0]
            new_pool['ext_ip'] = pool['ext_ip']
            vip_name_list.append(pool['name'])
            dst_nat_pools.append(new_pool)
            vip_address_book.append(priv_vip_addr)
            vip_address_book.append(pub_vip_addr)

    router_conf.update({'dst_nat_pools': dst_nat_pools})
    router_conf['addresses'].extend(vip_address_book) # extend addresbook and add private IPs for the VIPs


    #####
    # firewall rules
    #
    # note:
    #  - SRX pipeline does DNAT before matching firewall rules, so the transformed dstIp is used
    #       - so for rules which have dstAddress of a VIP, need to replace that with the mappedIp
    #           - no flag that tells you which these rules are, so need to check all dst_addrs
    #           against VIPs and then do the substitution
    #       - need to create destination NAT rulesets to match
    #  - SRX pipeline does SNAT after matching firewall rules, so the original srcIp is used
    #       - so for rules with src-nat enabled, no need to do anything special
    #       - just need to create the source NAT rulesets to match
    # todo: figure out the meaning of the various match_vip flags in Fortinet to determine
    # todo: create the src and dst nat rules
    #   - dst nat rules just have src_zone requirement
    #   - src nat rules have src_zone and dst_zone requirement
    # sample input
    # data:
    #     fw_policy:
    #         - name: PERMIT-WEB
    #           src_zone: zone0
    #           dst_zone: zone1
    #           action: permit
    #           match_rules:
    #             src_addrs:
    #                 - any
    #             dst_addrs:
    #                 - any
    #             applications:
    #                 - HTTP
    #                 - HTTPS
    #         - name: PERMIT-DNS
    #           src_zone: zone0
    #           dst_zone: zone1
    #           action: permit
    #           match_rules:
    #             src_addrs:
    #                 - INTERNAL_BLOCK1
    #                 - INTERNAL_BLOCK2
    #             dst_addrs:
    #                 - DNS_SERVERS
    #             applications:
    #                 - DNS
    #         - name: DENY-ALL
    #           src_zone: zone0
    #           dst_zone: zone1
    #           action: deny
    #           match_rules:
    #             src_addrs:
    #                 - any
    #             dst_addrs:
    #                 - any
    #             applications:
    #                 - any


    fw_policies = []
    src_nat_entries = []
    dst_nat_entries = []

    for rule in res['fw_policy']['rules']:
        if rule['status'] == 'disable':
            continue
        # this makes it easy to determine the new zone name
        t_in_zone = "::".join(rule['in_zone'])
        t_out_zone = "::".join(rule['out_zone'])
        in_zone = zone_map[t_in_zone]
        out_zone = zone_map[t_out_zone]
        if rule['action'] == 'accept':
            action = 'permit'
        else:
            action = 'deny'
        policy = {
            "name": rule.get('name', rule['id']), #name is not required, but id will always be present
            "src_zone": in_zone,
            "dst_zone": out_zone,
            "action": action,
            "match_rules": {
                "src_addrs": rule['src_addr'],
                "applications": rule['apps']
            }
        }
        # need to replace dstIP that is a VIP with the private IP it is mapped to
        # address book entries are present for both
        dstIps = []
        vip_rule = False
        for dst in rule['dst_addr']:
            if dst in vip_name_list:
                dstIps.append(f"{dst}-PRIV")
                vip_rule = True
            else:
                dstIps.append(dst)
        if vip_rule:
            dst_nat_entries.append(rule)  # will be used later to create the dst NAT rules

        policy['match_rules']['dst_addrs'] = dstIps
        # since we are already evaluating all the rules, this will save us time when we go to create the src nat rules
        if rule.get('nat') == 'enable' and rule.get('src_nat_enable') == 'enable':
            src_nat_entries.append(rule)
        fw_policies.append(policy)

    router_conf.update( {"fw_policy": fw_policies} )

    ####
    # destination nat rules
    #
    # when creating the firewall policies, we kept a list of policies that referenced destination addresses that were VIPs
    # so here we can just loop over those to create the necessary dNat rule-sets
    # todo: test this logic with more than 1 src zone. pretty sure it will work, but never know until it has been tested
    # todo: determine if a Fortinet firewall policy can have dst addresses that are VIPs and non-VIPs. If yes, will need to
    #   refine this logic since right now it assumes all dst addresses for the entry are VIPs.
    # sample data:
    #
    # data:
    #     dst_nat_pools:
    #         - name: pool1
    #           ext_ip: 1.1.1.1
    #           mapped_ip: 1.1.1.10
    #     dst_nat_rules:
    #         - src_zone: zone1
    #           rules:
    #             - src_addr: 0.0.0.0/0
    #               dst_addr: VIP1
    #               pool: pool1
    #               name: rule1

    dst_nat_rules = []
    dnat_zone_rules = defaultdict(list) # using this structure to collect list of rules per src zone

    rule_count = 0 # keeping rule count global so that I don't have to keep one per src zone
    for dnat in dst_nat_entries:

        t_in_zone = "::".join(dnat['in_zone'])
        in_zone = zone_map[t_in_zone]

        rules = []
        for dest in dnat['dst_addr']:
            rule = {
                'name': f"rule{rule_count}",
                'dst_addr': dest,
                'pool': dest,
                'src_addr': '0.0.0.0/0'
            }
            rules.append(rule)
            rule_count +=1
        dnat_zone_rules[in_zone].extend(rules)

    # j2 template needs a list of dictionaries with src zone and rules as keys
    # so need to transform the src zone indexed dict of rules as below
    # no doubt there is a better way to do all of this, but this works so sticking with it at this point
    for k in dnat_zone_rules.keys():
        t = dict()
        t['src_zone'] = k
        t['rules'] = dnat_zone_rules[k]
        dst_nat_rules.append(t)

    router_conf.update( {'dst_nat_rules': dst_nat_rules} )

    ####
    # source nat rules
    # sample data:
    #
    # data:
    #     src_nat_pools:
    #     - name: pool1
    #       start_ip: 1.1.1.1
    #       end_ip: 1.1.1.10
    #     - name: pool2
    #       prefix: 10.1.1.0/24
    #     src_nat_rules:
    #         - src_zone: zone1
    #           dst_zone: zone0
    #           rules:
    #             - src_addr: INSIDE
    #               dst_addr: 0.0.0.0/0
    #               pool: pool1
    #               name: rule1
    #

    src_nat_rules = []
    snat_zone_rules = defaultdict(list) # using this structure to collect list of rules per src zone
    rule_count = 0 # keeping rule count global so that I don't have to keep one per src zone - dst zone pair

    for snat in src_nat_entries:

        t_in_zone = "::".join(snat['in_zone'])
        t_out_zone = "::".join(snat['out_zone'])
        in_zone = zone_map[t_in_zone]
        out_zone = zone_map[t_out_zone]
        zone_pair = f"{in_zone}::{out_zone}"

        rules = []
        for src in snat['src_addr']:
            rule = {
                "name": f"rule{rule_count}",
                "dst_addr": "0.0.0.0/0",
                "pool": snat['src_nat_pool'],
                "src_addr": src
            }
            rules.append(rule)
            rule_count += 1
        snat_zone_rules[zone_pair].extend(rules)

    # j2 template needs a list of dictionaries with src zone and rules as keys
    # so need to transform the src zone indexed dict of rules as below
    # no doubt there is a better way to do all of this, but this works so sticking with it at this point
    for k in snat_zone_rules.keys():
        t = dict()
        t['src_zone'], t['dst_zone'] = k.split("::")
        t['rules'] = snat_zone_rules[k]
        src_nat_rules.append(t)

    router_conf.update( {'src_nat_rules': src_nat_rules} )

    #####
    #
    # static routes
    # notes: static routes with status='disable' are excluded by the TTP parser automatically
    # todo: support usage of next_hop_interface in static route. Need to translate the provided interface
    #   to the SRX interface. also need to work out SRX config if both IP and next-hop are provided
    # sample input
    # data:
    #     static_routes:
    #         - id: 0
    #           prefix: 1.1.1.0/24
    #           discard: enable
    #         - id: 1
    #           prefix: 10.1.1.0/24
    #           discard: disable
    #           next_hop_ip: 1.1.2.1
    #           next_hop_interface: reth0.1
    #

    static_routes = []
    static_route_count = 0
    for static_rt in res['static_routes']['routes']:
        static_routes.append(static_rt)
        if 'next_hop_interface' in static_rt.keys():
            nh_int = static_rt['next_hop_interface']
            static_routes[static_route_count]['next_hop_interface'] = f"{intf_map[nh_int]['name'].intf_map[nh_int]['unit']}"
        static_route_count +=1

    router_conf.update( {'static_routes': static_routes})


    ####
    # prefix-lists
    #
    # todo: handle ge and le settings for the prefix-lists
    # note: fortinet prefix-lists have actions: permit or deny in each entry, so I am creating both policy-statements
    #       and prefix-lists
    # note: for now the only prefix-list entry with deny action is last in the list and matches "any" prefix
    #       so going to treat that as the implicit deny and ignore
    #
    # sample input
    #
    # data:
    #     prefix_lists:
    #         - name: LIST1
    #           entries:
    #             - id: 1
    #               prefix: 1.1.1.0/24
    #             - id: 2
    #               prefix: 1.1.0.0/16

    pfx_lists = []
    action_map = {
        "permit" : "accept",
        "deny" : "reject"
    }
    for pfx_list in res['prefix_lists']['prefix_list']:
        name = pfx_list['name']
        t_pfx_list = {
            'name': name,
            'entries': []
        }
        for rule in pfx_list['rules']['rule']:
            if rule['prefix'] == 'any':
                continue
            t_pfx_entry = {
                'id': rule['id'],
                'prefix': rule['prefix'],
                'action': action_map[rule['action']]
            }
            t_pfx_list['entries'].append(t_pfx_entry)
        pfx_lists.append(t_pfx_list)

    router_conf.update( {'prefix_lists': pfx_lists})


    #####
    #
    # BGP
    # full bgp config options - https://docs.fortinet.com/document/fortigate/6.2.1/cli-reference/466620/router-bgp
    #
    # notes:
    #   - if a bgp neighbor has `shutdown = enable` in the config, the ttp parser will ignore the neighbor
    #     this way I don't have to deactivate it in the j2 template
    #   - skipping bgp confederation related config
    #   - skipping rr_client setting since it is not used in the sample config
    #   - skipping ipv4_af activation, assuming it is always enabled
    #   - skipping bgp add-path, assuming it is not enabled since it is not used in sample config
    #   - not handling interface command for BGP neighbors
    #   - turning on bgp multipath multi-as if either ibgp_mp or ebgp_mp is set in config
    #   - ignoring deterministic med setting, since not sure if user is allowed to also set always compare med with it
    #   - skipping allow_as_in setting since it is disabled in the sample config
    #   - skipping default_originate handling since it is disabled in the sample config
    #   - generally, not handling ANY BGP knobs that are not used in sample config
    # todo: handle bgp neighbor-group (aka peer-group) configuration. not used in sample config
    # todo: handle bgp network statements and aggregate prefix statements
    # todo: figure out how to deal with remote_private_as being enabled
    # todo: figure out how to redistribute routes for a protocol without any route-map into BGP
    #
    # note: send community options are standard|extended|both

    # sample input:
    #
    # data:
    #     bgp:
    #         ibgp_mp: enable
    #         ebgp_mp: enable
    #         router_id: 1.1.1.1
    #         local_as: 65001
    #         bestpath_aspath_ignore: disable
    #         always_comp_med: enable
    #         peers:
    #             - peer_ip: 1.1.1.2
    #               remote_as: 65002
    #               description: test
    #               nhop_self: enable
    #             - peer_ip: 2.1.1.1
    #               remote_as: 65003
    #               nhop_self: disable
    #               local_as_peer: 65003
    #


    bgp = {}
    required_keys = ['ibgp_mp', 'ebgp_mp', 'always_comp_med', 'bestpath_aspath_ignore', 'router_id', 'local_as']

    for k in required_keys:
        bgp[k] = res['bgp'][k]

    bgp['peers'] = res['bgp']['peers']['peer']
    bgp['redistribute'] = res['bgp']['redistribute']
    router_conf.update( {'bgp': bgp })


    #####
    # OSPF
    #
    # notes:
    #   - template excludes protocols from redistribution with status = disable
    #     - also, routemap key is skipped if not set. not set means config has '' as value
    #   - template excludes interfaces with status = disable
    #   - template excludes
    #   - auto_ref_bw for fortinet is expressed in Mbps. so 1000 is 1000Mbps aka 1Gbps
    #     max value = 1,000,000 which 1Tbps aka 1,000Gbps
    # todo: handle interface priority setting
    # todo: redistribution into OSPF from other protocols
    # todo: ospf distribute-list-in
    #   - juniper import route policy for OSPF is only allowed to filter external routes
    #   - fortinet has distribute-route-map-in which is supposed to "Filter incoming external routes by route-map."
    #   - going to interpert distribute-list in as filtering incoming external routes as well
    #   you cannot filter native OSPF routes
    # todo: handle nssa redistribution enable setting, not sure if there is a need to set it in JunOS
    # todo: handle ospf stub areas
    # todo: handle default-route origination and metric setting.
    # assumptions: ospf and bgp router-id are the same and the bgp config sets it
    #
    # sample output:
    #
    # data:
    #     ospf:
    #         router_id: 1.1.1.1
    #         dist_list_in: FOO
    #         ref_bw: 1g
    #         areas:
    #             - area: 0.0.0.1
    #               area_type: nssa
    #               stub_type: summary
    #               nssa_default_metric_type: 2
    #               nssa_default_metric: 10
    #               nssa_redis: enable
    #         interfaces:
    #             - interface: xe-0/0/0.75
    #               network: point-to-point
    #               area: 0.0.0.1
    #             - interface: xe-0/0/0.76
    #               network: point-to-point
    #               area: 0.0.0.1
    #         redistribute:
    #             - protocol: direct
    #               status: enable
    #               # status is not checked, since TTP template parsing ensures that protocols
    #               # where it is set to disable are ignored during parsing
    #               metric-type: 2
    #             - protocol: bgp
    #               status: enable
    #               metric-type: 2
    #


    ospf_intf_type = {
        "point-to-point": "p2p",
        "point-to-multipoint": "p2mp",
        "point-to-multipoint-non-broadcast": "nbma",
        "broadcast": "broadcast",
        "non-broadcast": "p2mp-over-lan"
    }

    ospf = deepcopy(res['ospf'])
    # need to change interface names to the ones in the SRX config
    # also need to add the area the interface should be part of
    for interface in ospf['interfaces']:
        t_intf = interface['interface']
        interface['interface'] = f"{intf_map[t_intf]['name']}.{intf_map[t_intf]['unit']}"
        interface['name'] = interface['interface']
        ipaddr = intf_map[t_intf]['ip'].split("/")[0]
        for network in ospf['networks']:
            prefix = network['prefix']
            if ip_address(ipaddr) in ip_network(prefix, strict=False):
                # strict=False required so the fact that host bits are set is ignored
                interface['area'] = network['area']
        interface['network'] = ospf_intf_type[interface['network']]

    ## convert ref_bw to the required format for JunOS
    ref_bw = res['ospf']['ref_bw']

    if (int(ref_bw) > 1000):
        t = "(^\d+)(\d\d\d)$"
        tt = re.match(t, str(ref_bw))
        ref_bw_str = f"{tt.group(1)}g"
    else:
        ref_bw_str = "1g"

    ospf['ref_bw'] = ref_bw_str


    router_conf.update( {'ospf': ospf})

    #####
    #
    # Config generation
    #
    #

    template_map = {
        'srx': ['srx-system.j2', 'srx-addresses.j2', 'srx-interfaces.j2', 'srx-zones.j2',
                'srx-applications.j2', 'srx-src-nat.j2', 'srx-dst-nat.j2', 'srx-zone-policy.j2',
                'srx-static-routes.j2', 'srx-prefix-list.j2', 'srx-bgp.j2', 'srx-ospf.j2']
    }

    assemble(j2_template_dir, router_conf, output_file, template_map[rt_type])


    # notes:
    # assumptions: just a single VDOM per device
    # assumptions: just the default VRF
    # assumptions: v6 configuration is not relevant, since BF doesn't support v6
    # todo: figure out the ospf config parsing and configuration building
    #   - ospf has a distribute-list in, need to figure out what to translate that to for Junos
    # todo: clean-up pass on j2_templates to use `contains` as a means to ignore entries that are disabled
    #   simplifies the code a lot, since don't need to check for that
    # todo: figure out community-list parsing. Not in sample config, so skipping for now
    # todo: for prefix-lists when turning into policy statements figure out how to handle ge and le settings
    #   - also see if we need to turn fortigate prefix-lists into JunOS prefix-lists at all since they are
    #   already being converted to policy-statements which allow for actions and prefix length matching
    # todo: figure out how to turn route-maps into policy-statements
    #       - route-maps in sample config are not actually used, so defering this
    #       - parsing work for route-maps is complete, though with new configs will need to verify that we are
    #       extracting all of the necessary attributes
    # todo: check if start_ip is lower then end_ip in any range. if not just flip them.
    #   - for now, there is only one spot in the sample config where this is the case, so going to just edit it.
    # todo: figure out if `firewall security-policy` is required
    # todo: figure out how interface access-lists are configured and used
    # todo: validate that we can ignore this line "set management-ip" under `interfaces`
    # todo: handle ICMP6 application definition. Ignoring for now, since they are not used in the config
    #       and not sure how to handle it in SRX config
    # todo: figure it if we need to handle exclude-addresses in the firewall address group config
    # todo: figure out how to handle firewall custom services with protocol =
    #         HTTP: HTTP - for web proxy.
    #         FTP: FTP - for web proxy.
    #         CONNECT: Connect - for web proxy.
    #         SOCKS-TCP: Socks TCP - for web proxy.
    #         SOCKS-UDP: Socks UDP - for web proxy.
    # note: ignore the SSLVPN_TUNNEL_ADDR1 fw_address, ssl.root fw_interface and any other SSL VPN related attributes
    # note: `mappedip` under the firewall.vip can be a range, but code only supports a single IP today
    # note: SRX has restrictions on use of address-sets for NAT, need to keep that in mind
    # note: SRX has restrictions on use of non-global address-books, so just put all addresses in a global address-book
    # note: in fw_service_custom['svc_name'] the apps can have an `iprange` field.
    #   - So far all examples have it set to 0.0.0.0
    #       - This assumption is baked into the creation of SRX applications
    # note: route-maps are converted to policy-statement
    # note: ttp template converts protocol connected to direct to match JunOS syntax

    #
    # Resources:
    # destination nat: https://www.fortinetguru.com/2019/10/policy-with-destination-nat/
    # central nat (src and dst nat config in UI)
    #   https://www.fortinetguru.com/2020/07/central-source-nat-and-destination-nat/


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', required=True,
                        help='Fortinet configuration file')
    parser.add_argument('-o', '--output', default='fortinet_to_srx.cfg',
                        help='Translated Configuration file')
    parser.add_argument('-t', '--ttp', default='ttp_templates',
                        help='Directory with TTP templates. Default value is "./ttp_templates"')
    parser.add_argument('-j', '--jinja2', default='j2_templates',
                        help='Translated Configuration file. Default value is "./j2_templates"')

    options = parser.parse_args()

    out_file = options.output
    if not Path(out_file).is_absolute():
        out_file = Path(out_file).absolute()

    in_file = Path(options.input).absolute()

    ttp_path = options.ttp
    if not Path(ttp_path).is_dir():
        print(f"Supplied path to TTP template directory  - {ttp_path} is invalid")
        exit()
    ttp_path = Path(ttp_path).absolute()

    j2_path = options.jinja2
    if not Path(j2_path).is_dir():
        print(f"Supplied path to Jinja2 template directory - {j2_path} is invalid")
        exit()
    j2_path = Path(j2_path).absolute()

    parse_results = parse_config(in_file, ttp_path)
    convert_config(parse_results, out_file, j2_path, "srx")