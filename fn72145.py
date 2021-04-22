# -*- coding: utf-8 -*-

"""
This program logins to one or more ACI fabrics and attempts to find specific
faults and/or affected hardware by the FN-72145.

Additional information of the FN can be found on:
https://www.cisco.com/c/en/us/support/docs/field-notices/721/fn72145.html

Copyright (c) 2018 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.0 (the "License"). You may obtain a copy of the
License at https://developer.cisco.com/docs/licenses
All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
"""

# Imported Libraries
import aiohttp
from aiohttp import ClientConnectorError, ClientSession, ClientResponse
import asyncio
import asyncssh
from asyncssh import PermissionDenied
from icmplib import ping
import logging
import re
from credentials import *


# Classes
class AsyncIterator:
    def __init__(self, seq):
        self.iter = iter(seq)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return next(self.iter)
        except StopIteration:
            raise StopAsyncIteration


class Error(Exception):
    """Base class for other custom exceptions"""
    pass


class AuthenticationError(Error):
    """Raised when unable to authenticate to a service"""
    pass


# Global Variables
API = 'https://%s/api'
FAULTS = ['F1222']
LOGGER = 'fn72145'
LOG_FILE = 'fn72145_check.log'
LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
AFFECTED_DEVICES = [
    "N9K-C9396TX", "N9K-C9396PX", "N9K-C93128TX", "N9K-C9332PQ", "N9K-C9372PX",
    "N9K-C9372TX", "N9K-C93120TX", "N9K-C9372PX-E", "N9K-C9372TX-E",
    "N9K-C93180YC-EX", "N9K-C93108TC-EX", "N9K-C93180LC-EX", "N9K-SUP-B+",
    "N9K-SUP-B", "N9K-SUP-A+", "N9K-SUP-A", "N9K-C9396TX=", "N9K-C9396PX=",
    "N9K-C93128TX=", "N9K-C9332PQ=", "N9K-C9372PX=", "N9K-C9372TX=",
    "N9K-C93120TX=", "N9K-C9372PX-E=", "N9K-C9372TX-E=", "N9K-C93180YC-EX=",
    "N9K-C93108TC-EX=", "N9K-C93180LC-EX=", "N9K-SUP-B+=", "N9K-SUP-B=",
    "N9K-SUP-A+=", "N9K-SUP-A=", "N9K-C9336PQ", "N9K-C9336PQ="
]
FLASH_MODELS = ['M500IT']
FLASH_REVS = ['MU01.00', 'MC02.00']
FIXED_RELS = ['13.2(10e)', '14.2(7f)', '15.1(4c)']


# Regular Expressions
TOPOLOGY_RE = r'topology/(pod-\d{1,2})/(node-\d{3,4})'
SUPSLOT_RE = r'/(supslot-\d{1,2})'
F1222_RE = r'%(topology)s/sys/diag/rule-ssd-acc-trig-forever' \
           r'/subj-\[%(topology)s/sys/ch%(supslot)s/sup\]' % \
           dict(topology=TOPOLOGY_RE, supslot=SUPSLOT_RE)
MNT_BF_RE = r'/dev/sda4 on /bootflash type ext4 \((r[w|o]),.+\)'
SPLIT_OS_RE = r'\.|\(|\)'
POH_RE = r'\s+\d+\s+Power_On_Hours\s+\dx(\d+\s+){3}(\w+\s+){2}[\W|\w]+\s+(\d+)'
SYS_UP_RE = r'Active supervisor uptime:\s+(\d+)\s+days,\s+(\d+)\s+hours,\s+(\d+)\s+minutes,\s+\d+\s+seconds'


# Temp variables
FABRICS = AsyncIterator(APICS)
USR = USER
PWD = PASS


# Functions
def get_logger():
    """Local file and console logging"""
    logger = logging.getLogger(LOGGER)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(LOG_FORMAT)
    # File handler
    fh = logging.FileHandler(LOG_FILE)
    fh.setFormatter(formatter)
    fh.setLevel(logging.DEBUG)
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    # Setup logger
    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger


log = get_logger()


async def apic_login(session: ClientSession, url: str):
    log.info(f'Authenticating to the APIC at {url.strip("/api")}')
    credentials = {'aaaUser': {'attributes': {'name': USR, 'pwd': PWD}}}
    try:
        async with session.post(
                url + '/aaaLogin.json',
                json=credentials,
                ssl=False
        ) as response:
            assert response.status == 200

    except AssertionError as e:
        log.warning(f'Unable to authenticate to the APIC at '
                    f'{url.strip("/api")}. Verify credentials.')
    except ClientConnectorError as e:
        log.warning(f'Cannot connect to APIC at {url.strip("/api")} . '
                    f'Verify network connectivity')


def dissect_version(ver: str) -> tuple:
    rel_, major_, minor_, patch_ = re.split(SPLIT_OS_RE, ver)
    minor_, patch_ = re.match(r'(\d+)([a-z]+)', minor_).groups()
    rel_, major_, minor_ = int(rel_), int(major_), int(minor_)
    return rel_, major_, minor_, patch_


def verify_fixed_version(nxos_ver: str) -> bool:
    fixed: bool = False
    if 'n9000-' in nxos_ver:
        nxos_ver = nxos_ver.strip('n9000-')
    log.info(f'Comparing {nxos_ver} NX-OS code against list of fixed releases.')
    rel, major, minor, patch = dissect_version(nxos_ver)
    if nxos_ver.startswith('14.0') or nxos_ver.startswith('15.0'):
        fixed = False
    elif rel < 13:
        fixed = False
    else:
        for release in FIXED_RELS:
            fix_rel, fix_major, fix_minor, fix_patch = dissect_version(release)
            patch_list = [i for i in [patch, fix_patch]]
            patch_list.sort(reverse=True)
            patch_idx = patch_list.index(patch)
            fix_patch_idx = patch_list.index(fix_patch)
            if (
                    rel >= fix_rel) and (
                    major >= fix_major) and (
                    minor >= fix_minor) and (
                    patch_idx >= fix_patch_idx
            ):
                fixed = True
            else:
                fixed = False

    return fixed


async def get_sup_info(session: ClientSession, url: str, topology: str) -> str:
    log.info(f'Querying APIC at {url.strip("/api")} '
             f'for {topology} supervisor information.')
    sup_model = None
    sup_query = f'eq(eqptSupC.dn,"{topology}")'
    query_filter = f'query-target-filter=and({sup_query})'
    try:
        async with session.get(
            url + f'/class/eqptSupC.json?{query_filter}',
            ssl=False
        ) as response:
            assert response.status == 200
            json_res = await response.json()
            totalcount, imdata = int(json_res['totalCount']), json_res['imdata']
            async for sup in AsyncIterator(imdata):
                attribs = sup['eqptSupC']['attributes']
                sup_model = attribs['model']
        return sup_model

    except AssertionError as e:
        log.error(f'Unable to retrieve supervisor information '
                  f'on APIC at {url.strip("/api")}.')


async def confirm_affected_device(
        session: ClientSession, url: str, node: str
) -> str:
    log.info(f'Querying APIC at {url.strip("/api")} '
             f'for {node} device information.')
    node_query = f'wcard(fabricNode.dn,"{node}")'
    query_filter = f'query-target-filter=and({node_query})'
    async with session.get(
        url +  f'/node/class/fabricNode.json?{query_filter}',
        ssl=False
    ) as response:
        assert response.status == 200
        json_res = await response.json()
        totalcount, imdata = int(json_res['totalCount']), json_res['imdata']
        async for fnode in AsyncIterator(imdata):
            attribs = fnode['fabricNode']['attributes']
            if attribs['fabricSt'] == 'active':
                sw_dn = attribs['dn']
                sw_model = attribs['model']
                sw_run_ver = attribs['version']
                if (
                        sw_model.startswith('N9K-C93')) and (
                        sw_model in AFFECTED_DEVICES
                ):
                    fixed = verify_fixed_version(sw_run_ver)
                    if not fixed:
                        log.critical(
                            f'{node} has been added to the list of '
                            f'impacted devices'
                        )

                        return node
                    else:
                        log.info(f'{node} is not affected by fn72145.')

                elif sw_model.startswith('N9K-C95'):
                    sup_model = None
                    for slot in [1, 2]:
                        topology = '%(sw_dn)s/sys/ch/supslot-%(slot)s/sup' % \
                                   dict(sw_dn=sw_dn, slot=slot)
                        sup_model = await get_sup_info(
                            session, url, topology
                        )
                        if (
                                sup_model is not None) and (
                                sup_model in AFFECTED_DEVICES
                        ):
                            fixed = verify_fixed_version(sw_run_ver)
                            if not fixed:
                                log.critical(f'{node} affected by fn72145.  Verify node\'s SSD uptime.')
                                return node
                            else:
                                log.info(f'{node} supslot-{slot} is not affected by fn72145.')




async def verify_devices(session: ClientSession, url: str) -> list:
    log.info(f'Querying APIC at {url.strip("/api")} '
             f'for affected SSDs on switches.')
    impacted_devices: list = []
    flash_mod_queries = ','.join([
        f'wcard(eqptFlash.model,"{model}")' for model in FLASH_MODELS])
    query_filter = f'query-target-filter=or({flash_mod_queries})'
    model_str = ', '.join(FLASH_MODELS)
    try:
        async with session.get(
            url +  f'/class/eqptFlash.json?{query_filter}',
            ssl=False
        ) as response:
            assert response.status == 200
            json_res = await response.json()
            totalcount, imdata = int(json_res['totalCount']), json_res['imdata']
            if totalcount == 0:
                log.info(f'No {model_str} SSDs found on APIC at '
                         f'{url.strip("/api")}')
            elif totalcount >= 1:
                log.warning(f'{model_str} SSDs found on APIC at '
                         f'{url.strip("/api")}')
                async for flash in AsyncIterator(imdata):
                    ssd_dn = flash['eqptFlash']['attributes']['dn']
                    ssd_model = flash['eqptFlash']['attributes']['model']
                    ssd_rev = flash['eqptFlash']['attributes']['rev']
                    if ssd_rev.upper() in FLASH_REVS:
                        ssd_match = re.match(
                            r'%s/sys/ch%s/sup/flash' % (
                                TOPOLOGY_RE, SUPSLOT_RE), ssd_dn
                        )
                        impacted = await confirm_affected_device(
                            session, url, ssd_match.group(2)
                        )
                        if impacted is not None:
                            impacted_devices.append(impacted)

        return impacted_devices

    except AssertionError as e:
        log.error(f'Unable to retrieve Nexus SSD Flash model information '
                    f'on APIC at {url.strip("/api")}.')


async def verify_apic_faults(session, url):
    log.info(f'Querying APIC at {url.strip("/api")} for SSD fault F1222.')
    fault_queries = ','.join([
        f'eq(faultInst.code,"{code}")' for code in FAULTS])
    query_filter = f'query-target-filter=or({fault_queries})'
    code_str = ', '.join(FAULTS)
    try:
        async with session.get(
            url + f'/class/faultInst.json?{query_filter}',
            ssl=False
        ) as response:
            assert response.status == 200
            json_res = await response.json()
            totalcount, imdata = int(json_res['totalCount']), json_res['imdata']
            faults = {}
            if totalcount == 0:
                log.info(f'No faults found for code(s) {code_str} at '
                         f'{url.strip("/api")}')
            elif totalcount >= 1:
                async for fault in AsyncIterator(imdata):
                    record = fault['faultInst']['attributes']
                    dn = record['dn']
                    code = record['code']
                    faults.setdefault(code, []).append(dn)
                    affected_node = re.match(F1222_RE, dn)
                    log.critical(f'Fault code(s) {code_str} found at '
                                 f'{url.strip("/api")} on {affected_node[1]} '
                                 f'{affected_node[2]}.')
        # print(faults)

    except AssertionError as e:
        log.warning(f'Unable to retrieve fault information on APIC at '
                    f'{url.strip("/api")}.')


def time_before_fail(
        node: str,
        pwr_on_hrs: int,
        sys_up_days: int,
        sys_up_hrs: int,
        rw_status: str
):
    threshold_: int = 28224
    hrs_for_reload_: int = 1008
    if pwr_on_hrs < threshold_:
        years = (threshold_ - pwr_on_hrs) // 8760
        days = ((threshold_ - pwr_on_hrs) % 8760) // 24
        weeks = days // 7
        days = days - (weeks * 7)
        log.warning(
            f'{node} is {years} year(s), {weeks} week(s), '
            f'{days} day(s) away from crash and/or RO state.'
        )

    elif pwr_on_hrs >= threshold_:
        sys_up_time = (sys_up_days * 24) + sys_up_hrs
        if (
                rw_status == 'rw') and (
                sys_up_time < hrs_for_reload_
        ):
            weeks = (((hrs_for_reload_ - sys_up_time) // 24) - sys_up_days) // 7
            days = (((hrs_for_reload_ - sys_up_time) // 24) - sys_up_days) % 7
            hours = 24 - sys_up_hrs
            log.warning(
                f'{node} has exceeded Power_On_Hours limit. '
                f'Time left before RO state: {weeks} week(s), {days} day(s), '
                f'{hours} hour(s).'
            )
        elif (
                rw_status == 'rw') and (
                sys_up_time >= hrs_for_reload_
        ):
            weeks = (((sys_up_time - hrs_for_reload_) // 24) + sys_up_days) // 7
            days = (((sys_up_time - hrs_for_reload_) // 24) + sys_up_days) % 7
            hours = sys_up_hrs
            log.critical(
                f'{node} has exceeded Power_On_Hours limit and the 6 weeks '
                f'threshold but it\'s still in RW state. '
                f'Schedule a switch reload ASAP.'
            )
        elif rw_status == 'ro':
            log.critical('{node} bootflash is in RO mode. A switch reboot is '
                         'necessary.')


async def query_nxos_switches(node, node_ip):
    log.info(f'Verifying Power_On_Hours on {node} at IP {node_ip}')
    cat_smartctl = 'cat /mnt/pss/smartctl_full_dump.log ' \
                  '| tail -n 103 ' \
                  '| egrep "Power_On_Hours"'
    mnt_bootflash = 'mount | grep bootflash'
    sh_uptime = 'show system uptime'
    try:
        async with asyncssh.connect(
                node_ip,
                username=USR,
                password=PWD,
                client_keys=None,
                known_hosts=None
        ) as conn:
            poh_result = await conn.run(cat_smartctl, check=True)
            rw_status_result = await conn.run(mnt_bootflash, check=True)
            uptime_result = await conn.run(sh_uptime, check=True)
            pow_on_hrs = int(re.findall(
                POH_RE, str(poh_result.stdout))[-1][-1])
            rw_status = (re.findall(
                MNT_BF_RE, str(rw_status_result.stdout)))[0]
            sys_up_time = (re.findall(
                SYS_UP_RE, str(uptime_result.stdout)))[-1][:2]
            time_before_fail(
                node, pow_on_hrs, int(sys_up_time[0]),
                int(sys_up_time[1]), rw_status
            )

    except PermissionDenied as e:
        log.error(f'Permission denied to SSH to Nexus switch at {node_ip}.'
                    f'Verify credentials.')
    except TimeoutError as e:
        log.error(f'Unable to connect to Nexus switch at {node_ip}. '
                    f'Verify network connectivity.')


def create_query_filter(
        obj: object,
        obj_class: str,
        obj_attr: str,
        query_type: str = 'contains',
        mode: str = 'single'
) -> str:
    supported_modes = ['single', 'multi']
    supported_queries = ['contains']
    if mode not in supported_modes:
        raise TypeError(
            'Provided mode is not supported for create_query_filter()'
        )
    if query_type not in supported_queries:
        raise TypeError(
            'Provided query_type is not supported for create_query_filter()'
        )
    query = 'wcard'
    query_filter = f'query-target-filter=and(%s)'
    if mode == 'multi':
        query_filter = f'query-target-filter=or(%s)'
    if mode == 'single':
        obj_query = f'%(query)s(%(obj_class)s.%(obj_attr)s,"%(obj)s")' % dict(
            query=query, obj_class=obj_class, obj_attr=obj_attr, obj=obj
        )
        query_filter = f'query-target-filter=and({obj_query})'
    elif mode == 'multi':
        obj_query = f'%(query)s(%(obj_class)s.%(obj_attr)s,"%(obj)s")' % dict(
            query=query, obj_class=obj_class, obj_attr=obj_attr, obj=obj
        )
        query_filter = f'query-target-filter=or({obj_query})'

    return query_filter


async def get_count_and_data(response: ClientResponse) -> tuple:
    assert response.status == 200
    json_res = await response.json()
    total_count, imdata = int(json_res['totalCount']), json_res['imdata']
    return total_count, imdata


async def get_ssh_ip(session: ClientSession, url: str, node: str) -> dict:
    log.info(f'Querying APIC at {url.strip("/api")} for '
             f'reachable SSH IP address for {node}')
    address_mgmt_classes = ['mgmtRsOoBStNode', 'mgmtRsInBStNode']
    node_ip_dict: dict = {}
    node_ip_dict.setdefault(node)
    node_ip_dict[node]: dict = {}
    try:
        mgmt_class = address_mgmt_classes[0]
        query_filter = create_query_filter(node, mgmt_class, 'dn')
        async with session.get(
                url + f'/node/class/{mgmt_class}.json?{query_filter}',
                ssl=False
        ) as response:
            totalcount, imdata = await get_count_and_data(response)
            if totalcount != 0:
                async for mgmt_node in AsyncIterator(imdata):
                    attribs = mgmt_node[mgmt_class]['attributes']
                    ssh_addr = attribs['addr'].split('/')[0]
                    node_ip_dict[node].setdefault(mgmt_class)
                    node_ip_dict[node][mgmt_class] = ssh_addr

        mgmt_class = address_mgmt_classes[1]
        query_filter = create_query_filter(node, mgmt_class, 'dn')
        async with session.get(
                url + f'/node/class/{mgmt_class}.json?{query_filter}',
                ssl=False
        ) as response:
            totalcount, imdata = await get_count_and_data(response)
            if totalcount != 0:
                async for mgmt_node in AsyncIterator(imdata):
                    attribs = mgmt_node[mgmt_class]['attributes']
                    ssh_addr = attribs['addr'].split('/')[0]
                    node_ip_dict[node].setdefault(mgmt_class)
                    node_ip_dict[node][mgmt_class] = ssh_addr

        return node_ip_dict

    except Exception as e:
        print(str(e), 'This was not good')


async def main():
    try:
        jar = aiohttp.CookieJar(unsafe=True)
        nodes_ssh_dict: dict = {}

        async for apic in FABRICS:
            async with ClientSession(cookie_jar=jar) as session:
                tasks = []
                url = API % apic
                await apic_login(session, url)
                await verify_apic_faults(session, url)
                impacted_devices = await verify_devices(session, url)
                async for node in AsyncIterator(impacted_devices):
                    ssh_info = await get_ssh_ip(session, url, node)
                    nodes_ssh_dict.update(ssh_info)

        async for node in AsyncIterator(nodes_ssh_dict):
            if 'mgmtRsOoBStNode' in nodes_ssh_dict[node].keys():
                node_ip = nodes_ssh_dict[node]['mgmtRsOoBStNode']
            elif 'mgmtRsOoBStNode' not in nodes_ssh_dict[node].keys():
                node_ip = nodes_ssh_dict[node]['mgmtRsInBStNode']
            host = ping(node_ip, count=5, interval=0.2, privileged=False)
            if host.is_alive:
                log.info(
                    f'Attempting SSH connection to {node} '
                    f'at oobMgmt {host.address}')
                power_on_hrs = await query_nxos_switches(node, host.address)
                # print(power_on_hrs)
            else:
                log.error(
                    f'{node} is unreachable via SSH '
                    f'on {host.address}. Unable to verify.'
                )

    except Exception as e:
        print(str(e), 'Exception happened on main')


# Main check
if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main())
        loop.run_until_complete(asyncio.sleep(0.250))
    finally:
        loop.close()