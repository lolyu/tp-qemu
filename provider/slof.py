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
import logging
import threading
import socket
import queue
import select
import os


class PollableQueue(queue.Queue):
    def __init__(self, name):
        super(PollableQueue, self).__init__()
        self.name = name
        self._put_socket, self._get_socket = socket.socketpair()

    def fileno(self):
        return self._get_socket.fileno()

    def put(self, item):
        super(PollableQueue, self).put(item)
        self._put_socket.send(b"i")

    def get(self):
        self._get_socket.recv(1)
        return super(PollableQueue, self).get()


class SerialLogReader(threading.Thread):
    def __init__(self, vm, prefix="SLOF", suffix="Successfully loaded"):
        super(SerialLogReader, self).__init__(name=vm.name, group=None,
                                              target=None)
        self.filename = vm.serial_console_log
        self.prefix = prefix
        self.suffix = suffix
        self._stop_event = threading.Event()
        self.queue = PollableQueue(vm.name)

    def run(self):
        if not os.path.isfile(self.filename):
            time.sleep(30)
        try:
            fd = open(self.filename)
        except Exception as e:
            logging.debug("failed to open serial log: %s", str(e))
        else:
            content = []
            while not self._stop_event.is_set():
                line = fd.readline()
                if not line:
                    continue
                if self.prefix in line or content:
                    content.append(line)
                if self.suffix in line:
                    self.queue.put(list(content))
                    content.clear()
        logging.debug("Terminate serial log reader thread.")

    def join(self, timeout=None):
        self._stop_event.set()
        super(SerialLogReader, self).join(timeout=timeout)


def get_boot_content(timeout=300):
    pq = [thread.queue for thread in threading.enumerate()
          if isinstance(thread, SerialLogReader)]
    start = time.time()
    while True:
        can_read, _, _ = select.select(pq, [], [], 0)
        for r in can_read:
            start = time.time()
            item = r.get()
            logging.debug("Get content from %s:\n%s\n" % (r.name, item))
            yield item
        if time.time() > start + timeout:
            raise TimeoutError("%d timeout in waiting for boot content" %
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
