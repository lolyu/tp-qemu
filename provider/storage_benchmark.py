"""
Module for providing storage benchmark tools for testing block device.

Available function:
- generate_instance: Generate a instance by specified storage benchmark class
                     to test block io by specified benchmark tool.

Available class:
- StorageBenchmark: Define a class provides common methods to test block io.
- Iozone: Define a class provides methods to test file I/O performance by
          iozone benchmark.
- Fio: Define a class provides methods to test block I/O performance by
       fio benchmark.
"""

import logging
import os
import re

from platform import machine

from virttest import utils_misc

from avocado import TestError

GIT_DOWNLOAD = 'git'
CURL_DOWNLOAD = 'curl'

TAR_UNPACK = 'tar'


class StorageBenchmark(object):
    """
    Create a Benchmark class which provides common interface(method) for
    using Benchmark tool to run test.

    """
    cmds = {'linux': {'_symlinks': 'ln -s -f %s %s',
                      '_list_pid': 'pgrep -xl %s',
                      '_kill_pid': 'killall %s',
                      '_rm_file': 'rm -rf {}'},
            'windows': {'_symlinks': 'mklink %s %s',
                        '_list_pid': 'TASKLIST /FI "IMAGENAME eq %s',
                        '_kill_pid': 'TASKKILL /F /IM %s /T',
                        '_rm_file': 'RD /S /Q "{}"'}}
    tar_map = {'.tar': '-xvf', '.tar.gz': '-xzf',
               '.tar.bz2': '-xjf', '.tar.Z': '-xZf'}
    download_cmds = {GIT_DOWNLOAD: 'rm -rf {0} && git clone {1} {0}',
                     CURL_DOWNLOAD: 'curl -o {0} {1}'}
    unpack_cmds = {TAR_UNPACK: '_tar_unpack_file'}

    def __init__(self, os_type, session, name):
        """
        :param session: session connected guest
        :param name: the name of benchmark
        :type name: str
        """
        self.session = session
        self.name = name
        self.os_type = os_type
        self.env_files = []

    def __getattr__(self, item):
        try:
            return self.cmds[self.os_type][item]
        except KeyError as e:
            raise AttributeError(str(e))

    def session_cmd(self, cmd, timeout=60):
        """ Session command. """
        self.session.cmd(cmd, timeout)

    def make_symlinks(self, src, dst):
        """
        Make symlinks between source file and destination file by force.

        :param src: source file
        :type src: str
        :param dst: destination file
        :type dst: str
        """
        self.session.cmd(self._symlinks % (src, dst))
        self.env_files.append(dst)

    def _wait_procs_done(self, timeout=1800):
        """
        Wait all the processes are done.

        :param timeout: timeout for waiting
        :type timeout: float
        """
        logging.info('Checking the currently running %s processes.' % self.name)
        if not utils_misc.wait_for(
                lambda: self.name not in self.session.cmd_output(
                    self._list_pid % self.name), timeout, step=3.0):
            raise TestError(
                'Not all %s processes done in %s sec.' % (self.name, timeout))

    def _kill_procs(self):
        """Kill the specified processors by force."""
        logging.info('Killing all %s processes by force.' % self.name)
        self.session.cmd_output(self._kill_pid % self.name, timeout=120)

    def _remove_env_files(self, timeout=300):
        """
        Remove the environment files includes downloaded files, installation
        files and others related to benchmark.

        :param timeout: timeout for removing
        :type timeout: float
        """
        logging.info('Removing the environment files.')
        cmds = (self._rm_file.format(f) for f in self.env_files)
        self.session.cmd(' && '.join(cmds), timeout=timeout)

    def download_benchmark(self, mode, url, dst, timeout=300):
        """
        Download a benchmark tool to destination file.

        :param mode: the mode of downloading, e.g, git, curl
        :type mode: str
        :param url: the url downloaded
        :type url: str
        :param dst: download the file to destination file
        :param timeout: timeout for downloading
        :type timeout: float
        """
        self.session.cmd(self.download_cmds[mode].format(dst, url), timeout)
        self.env_files.append(dst)

    def _tar_unpack_file(self, src, dst, timeout=300):
        """Unpack file by tar."""
        cmd = 'mkdir -p {0} && tar {1} {2} -C {0}'.format(
            dst, self.tar_map[re.search(r'\.tar\.?(\w+)?$', src).group()], src)
        self.session.cmd(cmd, timeout=timeout)

    def unpack_file(self, mode, src, dst, timeout=300):
        """
        Unpack file from source file to destination directory.

        :param mode: the mode of unpacking, e.g, tar, unzip
        :type mode: str
        :param src: source file
        :type src: str
        :param dst: destination directory
        :type dst: str
        :param timeout: timeout for unpacking
        :type timeout: float
        """
        getattr(self, self.unpack_cmds[mode])(*(src, dst, timeout))
        self.env_files.append(dst)

    def _install_linux(self, src, dst, timeout):
        """
        Install a package from source file to destination directory in linux.
        """
        self.session.cmd(
            "cd %s && ./configure --prefix=%s && make && make install" % (
                src, dst), timeout=timeout)

    def _install_win(self, src, dst, timeout):
        """
        Install a package from source file to destination directory in windows.
        """
        def _find_exe_file():
            """
            Find the path of the given executable file in windows.
            """
            cmd_dir = r'CD %s && DIR /S /B %s.exe' % (dst, self.name)
            s, o = self.session.cmd_status_output(cmd_dir, timeout=timeout)
            if not s:
                return '"{}"'.format(o.splitlines()[0])
            return None

        cmd = utils_misc.set_winutils_letter(
            self.session, r'msiexec /a "%s" /qn TARGETDIR="%s"' % (src, dst))
        self.session.cmd_output(cmd, timeout=timeout)
        if not utils_misc.wait_for(
                lambda: _find_exe_file(), timeout, step=3.0):
            raise TestError('Failed to install fio under %.2f.' % timeout)

    def install(self, src, dst, timeout=300):
        """
        Install a package from source file to destination directory.

        :param src: source file
        :type src: str
        :param dst: destination directory
        :type dst: str
        :param timeout: timeout for installing
        :type timeout: float
        """
        install_map = {'linux': '_install_linux', 'windows': '_install_win'}
        getattr(self, install_map[self.os_type])(src, dst, timeout)
        self.env_files.append(dst)

    def run(self, cmd, timeout=600):
        """
        Execute the benchmark command.

        :param cmd: executed command
        :type cmd: str
        :param timeout: timeout for executing command
        :type timeout: float
        :return: output of running command
        :rtype: str
        """
        return self.session.cmd(cmd, timeout=timeout)

    def clean(self, timeout=1800, force=False):
        """
        Clean benchmark tool packages and processes after testing inside guest.

        :param timeout: timeout for cleaning
        :type timeout: float
        :param force: if is True, kill the running processes
                      by force, otherwise wait they are done
        :type force: bool
        """
        if force:
            self._kill_procs()
        else:
            self._wait_procs_done(timeout)
        self._remove_env_files()

    def __enter__(self):
        """Enter context."""
        return self

    def __exit__(self, etype, evalue, traceback):
        """Exit context by calling clean with default arguments."""
        self.clean()


class IozoneLinuxCfg(object):
    def __init__(self, params, session):
        version = params.get('iozone_version', 'iozone3_483')
        self.download_url = ('http://www.iozone.org/src/current/%s.tar' % version)
        self.download_path = os.path.join('/home', 'iozone.tar')
        self.iozone_dir = os.path.join('/home/iozone_inst', version)
        self.arch = 'linux-AMD64' if 'x86_64' in machine() else 'linux-powerpc64'
        self.cmd = 'cd %s/src/current && make %s' % (self.iozone_dir, self.arch)
        self.iozone_path = '%s/src/current/iozone' % self.iozone_dir
        self.setups = {'download_benchmark': (CURL_DOWNLOAD,
                                              self.download_url,
                                              self.download_path),
                       'unpack_file': (TAR_UNPACK, self.download_path,
                                       '/home/iozone_inst'),
                       'session_cmd': (self.cmd, 300)}
        self.setups_order = ['download_benchmark', 'unpack_file', 'session_cmd']


class IozoneWinCfg(object):
    def __init__(self, params, session):
        label = params.get('win_utils_label', 'WIN_UTILS')
        drive_letter = utils_misc.get_winutils_vol(session, label)
        self.cmd = 'set nodosfilewarning=1 && set CYGWIN=nodosfilewarning'
        self.iozone_path = drive_letter + r':\Iozone\iozone.exe'
        self.setups = {'session_cmd': (self.cmd, 300)}
        self.setups_order = ['session_cmd']


class Iozone(StorageBenchmark):
    def __init__(self, params, session):
        self.os_type = params['os_type']
        super(Iozone, self).__init__(self.os_type, session, 'iozone')
        self.cfg_map = {'linux': IozoneLinuxCfg, 'windows': IozoneWinCfg}
        self.cfg = self.cfg_map[self.os_type](params, session)
        for method in self.cfg.setups_order:
            getattr(self, method)(*self.cfg.setups[method])

    def run(self, cmd_options='-a', timeout=1800):
        """
        Run iozone test inside guest.

        :param cmd_options: iozone command options, e.g: -azR -r 64k -n 1G -g
                            1G -M -f /home/test
        :type cmd_options: str
        """
        cmd = ' '.join((self.cfg.iozone_path, cmd_options))
        return super(Iozone, self).run(cmd, timeout)


class FioLinuxCfg(object):
    def __init__(self, params, session):
        self.download_url = 'git://github.com/axboe/fio.git'
        self.download_path = os.path.join('/home', 'fio_repo')
        self.fio_inst = os.path.join('/home', 'fio_inst')
        self.fio_path = '%s/bin/fio' % self.fio_inst
        self.setups = {'download_benchmark': (GIT_DOWNLOAD,
                                              self.download_url,
                                              self.download_path),
                       'install': (self.download_path, self.fio_inst)}
        self.setups_order = ['download_benchmark', 'install']


class FioWinCfg(object):
    def __init__(self, params, session):
        label = params.get('win_utils_label', 'WIN_UTILS')
        utils_letter = utils_misc.get_winutils_vol(session, label)
        arch = params.get('vm_arch_name', 'x84_64')
        self.fio_inst = {'x86_64': r'C:\Program Files (x86)\fio',
                         'i686': r'C:\Program Files\fio'}
        self.fio_msi = {'x86_64': r'%s:\fio-x64.msi' % utils_letter,
                        'i686': r'%s:\fio-x86.msi' % utils_letter}
        self.fio_path = r'"%s\fio\fio.exe"' % self.fio_inst[arch]
        self.setups = {'install': (self.fio_msi[arch], self.fio_inst[arch], 300)}
        self.setups_order = ['install']


class Fio(StorageBenchmark):
    def __init__(self, params, session):
        self.os_type = params['os_type']
        super(Fio, self).__init__(self.os_type, session, 'fio')
        self.cfg_map = {'linux': FioLinuxCfg, 'windows': FioWinCfg}
        self.cfg = self.cfg_map[self.os_type](params, session)
        for method in self.cfg.setups_order:
            getattr(self, method)(*self.cfg.setups[method])

    def run(self, cmd_options, timeout=1800):
        """
        Run fio test inside guest.

        :param cmd_options: fio command options, e.g, --filename=/home/test
                            --direct=1 --rw=read --bs=64K --size=1000M
                            --name=test
        :type cmd_options: str
        """
        cmd = ' '.join((self.cfg.fio_path, cmd_options))
        return super(Fio, self).run(cmd, timeout)


def generate_instance(params, session, name):
    """
    Generate a instance with the given name class.

    :param params: dictionary with the test parameters
    :param session: session connected guest
    :param name: benchmark name
    :type name: str
    :return: instance with the given name class
    :rtype: StorageBenchmark object
    """
    return {'fio': Fio, 'iozone': Iozone}[name](params, session)
