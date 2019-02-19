"""
Module for providing common interface to test SLOF component.

Available functions:
 - get_boot_content: Get the specified content of SLOF by reading the serial
                     log.
 - wait_for_loaded: Wait for loading the SLOF.
 - get_booted_devices: Get the device info which tried to load in the SLOF
                       stage.
 - verify_boot_device: Verify whether the vm is booted from the specified
                       device.
 - check_error: Check if there are error info in the SLOF content.
"""

import re
import time
import os
import asyncio
import logging

from contextlib import suppress


kue = asyncio.Queue()
open_fds = {}
_loop = None


async def get_line(fd):
    try:
        return fd.readline()
    except asyncio.CancelledError:
        print("GOT CANCELLED")


async def content_producer(filename, prefix, suffix):
    if not os.path.isfile(filename):
        await asyncio.sleep(30)
    try:
        fd = open_fds.setdefault(filename, open(filename))
    except Exception as e:
        logging.debug("failed to open serial log: %s", str(e))
    else:
        content = []
        while True:
            try:
                await asyncio.sleep(0)
                line = await get_line(fd)
                if not line:
                    continue
                if prefix in line or content:
                    content.append(line)
                if suffix in line:
                    await kue.put(list(content))
                    content.clear()
            except asyncio.CancelledError as e:
                # task.cancel arranges a CancelledError to be thrown into the
                # wrapped coroutine on the next cycle.
                # here we catch the error and clean up.
                logging.debug("Cancel task for file: %s" % filename)
                open_fds.pop(filename)
                fd.close()
                raise e


async def _get_boot_content():
    content = await kue.get()
    kue.task_done()
    return content


def get_boot_content(timeout=300):
    global _loop
    return _loop.run_until_complete(
        asyncio.wait_for(_get_boot_content(), timeout))


def start_loop(filenames, prefix="SLOF", suffix="Successfully loaded"):
    global _loop
    _loop = asyncio.get_event_loop()
    tasks = [_loop.create_task(content_producer(filename, prefix, suffix))
             for filename in filenames]
    return tasks


def exit_loop(tasks=None):
    global _loop
    if tasks is None:
        tasks = asyncio.all_tasks(_loop)
    for task in tasks:
        task.cancel()
        with suppress(asyncio.CancelledError):
            _loop.run_until_complete(task)
    _loop.close()


def wait_for_loaded(vm, test, start_pos=0, start_str='SLOF',
                    end_str='Successfully loaded', timeout=300):
    """
    Wait for loading the SLOF.

    :param vm: VM object
    :param test: kvm test object
    :param start_pos: start position which start to read
    :type start_pos: int
    :param start_str: start string
    :type start_str: int
    :param end_str: end string
    :type end_str: str
    :param timeout: time out for waiting
    :type timeout: float
    :return: content list and next position of the end of the content if found
             the the whole SLOF contents, otherwise return None and the
             position of start string.
    :rtype: tuple(list, int)
    """
    file_timeout = 30
    if not utils_misc.wait_for(lambda: os.path.isfile(vm.serial_console_log),
                               file_timeout):
        test.error('No found serial log in %s sec.' % file_timeout)

    end_time = timeout + time.time()
    while time.time() < end_time:
        content, start_pos = get_boot_content(vm, start_pos, start_str, end_str)
        if content:
            logging.info('Output of SLOF:\n%s' % ''.join(content))
            return content, start_pos
    test.fail(
        'No found corresponding SLOF info in serial log during %s sec.' %
        timeout)


def get_booted_devices(content):
    """
    Get the device info which tried to load in the SLOF stage.

    :param content: SLOF content
    :type content: list
    :return: device booted
    :rtype: dict
    """
    position = 0
    devices = {}
    for line in content:
        ret = re.search(r'(\s+Trying to load:\s+from:\s)(/.+)(\s+\.\.\.)',
                        line)
        if ret:
            devices[position] = ret.group(2)
            position += 1
    return devices


def verify_boot_device(content, parent_bus_type, child_bus_type, child_addr,
                       sub_child_addr=None, position=0):
    """
    Verify whether the vm is booted from the specified device.

    :param content: SLOF content
    :type content: list
    :param parent_bus_type: type of parent bus of device
    :type parent_bus_type: str
    :param child_bus_type: type of bus of device
    :type child_bus_type: str
    :param child_addr: address of device bus
    :type child_addr: str
    :param sub_child_addr: address of device child bus
    :type sub_child_addr: str
    :param position: position in all devices in SLOF content
    :type position: int
    :return: true if booted from the specified device
    :rtype: bool
    """
    pattern = re.compile(r'^0x0?')
    addr = pattern.sub('', child_addr)
    if sub_child_addr:
        sub_addr = pattern.sub('', sub_child_addr)

    pattern = re.compile(r'/\w+.{1}\w+@')
    devices = get_booted_devices(content)
    for k, v in devices.items():
        if int(k) == position:
            logging.info('Position [%d]: %s' % (k, v))
            break

    if position in devices:
        name = devices[position]
        info = ('Check whether the device({0}@{1}@{2}) is the {3} bootable '
                'device.'.format(parent_bus_type, child_bus_type,
                                 child_addr, position))
        if sub_child_addr:
            info = ('Check whether the device({0}@{1}@{2}@{3}) is the {4} '
                    'bootable device.'.format(parent_bus_type, child_bus_type,
                                              child_addr, sub_child_addr,
                                              position))
        logging.info(info)
        if parent_bus_type == 'pci':
            # virtio-blk, virtio-scsi and ethernet device.
            if child_bus_type == 'scsi' or child_bus_type == 'ethernet':
                if addr == pattern.split(name)[2]:
                    return True
            # pci-bridge, usb device.
            elif child_bus_type == 'pci-bridge' or child_bus_type == 'usb':
                if (addr == pattern.split(name)[2] and
                        sub_addr == pattern.split(name)[3]):
                    return True
        elif parent_bus_type == 'vdevice':
            # v-scsi device, spapr-vlan device.
            if child_bus_type == 'v-scsi' or child_bus_type == 'l-lan':
                if addr == pattern.split(name)[1]:
                    return True
        else:
            return False
    else:
        logging.debug(
            'No such device at position %s in all devices in SLOF contents.' %
            position)
        return False


def check_error(test, content):
    """
    Check if there are error info in the SLOF content.

    :param test: kvm test object
    :param content: SLOF content
    :type content: list
    """
    for line in content:
        if re.search(r'error', line, re.IGNORECASE):
            test.fail('Found errors: %s' % line)
    logging.info("No errors in SLOF content.")
