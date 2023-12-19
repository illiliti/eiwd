#!/usr/bin/python3

from argparse import ArgumentParser, Namespace, SUPPRESS
from configparser import ConfigParser
from collections import namedtuple
from shutil import copy, copytree, which, rmtree
from glob import glob

import os
import ctypes
import fcntl
import sys

libc = ctypes.cdll['libc.so.6']
libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, \
			ctypes.c_ulong, ctypes.c_char_p)

# Using ctypes to load the libc library is somewhat low level. Because of this
# we need to define our own flags/options for use with mounting.
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_STRICTATIME = 1 << 24
STDIN_FILENO = 0
TIOCSTTY = 0x540E

MountInfo = namedtuple('MountInfo', 'fstype source target options flags')
DevInfo = namedtuple('DevInfo', 'target linkpath')

mounts_common = [
	MountInfo('sysfs', 'sysfs', '/sys', '', MS_NOSUID|MS_NOEXEC|MS_NODEV),
	MountInfo('proc', 'proc', '/proc', '', MS_NOSUID|MS_NOEXEC|MS_NODEV),
	MountInfo('devpts', 'devpts', '/dev/pts', 'mode=0620', MS_NOSUID|MS_NOEXEC),
	MountInfo('tmpfs', 'tmpfs', '/dev/shm', 'mode=1777',
					MS_NOSUID|MS_NODEV|MS_STRICTATIME),
	MountInfo('tmpfs', 'tmpfs', '/run', 'mode=0755',
					MS_NOSUID|MS_NODEV|MS_STRICTATIME),
	MountInfo('tmpfs', 'tmpfs', '/tmp', '', 0),
	MountInfo('tmpfs', 'tmpfs', '/etc', '', 0),
	MountInfo('tmpfs', 'tmpfs', '/usr/share/dbus-1', 'mode=0755',
					MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME),
]

dev_table = [
	DevInfo('/proc/self/fd', '/dev/fd'),
	DevInfo('/proc/self/fd/0', '/dev/stdin'),
	DevInfo('/proc/self/fd/1', '/dev/stdout'),
	DevInfo('/proc/self/fd/2', '/dev/stderr')
]

def mount(source, target, fs, flags, options=''):
	'''
		Python wrapper for libc mount()
	'''
	ret = libc.mount(source.encode(), target.encode(), fs.encode(), flags,
				options.encode())
	if ret < 0:
		errno = ctypes.get_errno()
		raise Exception("Could not mount %s (%d)" % (target, errno))

#
# Custom argparse.Namespace class to stringify arguments in a way that can be
# directly passed to the test environment as kernel arguments. This also removes
# any None, False, or [] arguments.
#
class RunnerNamespace(Namespace):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

	def to_cmd(self):
		ret = ''
		for k, v in self.__dict__.items():
			if v in [None, False, [], '']:
				continue

			if type(v) is list:
				ret += '%s=%s ' % (k, ','.join(v))
			else:
				ret += '%s=%s ' % (k, str(v))

		return ret.strip()

#
# The core arguments needed both inside and outside the test environment
#
class RunnerCoreArgParse(ArgumentParser):
	def __init__(self, *args, **kwargs):
		ArgumentParser.__init__(self, *args, **kwargs)

		self.add_argument('--start', '-s',
				help='Custom init process in virtual environment',
				dest='start',
				default=None,
				type=os.path.abspath)
		self.add_argument('--verbose', '-v', metavar='<list>',
				type=lambda x: x.split(','),
				help='Comma separated list of applications',
				dest='verbose',
				default=[])
		self.add_argument('--debug', '--dbg', '-d',
				action='store_true',
				help='Enable test-runner debugging',
				dest='dbg')
		self.add_argument('--log', '-l',
				type=os.path.abspath,
				help='Directory for log files')
		self.add_argument('--monitor', '-m',
				type=os.path.abspath,
				help='Enables iwmon output to file')
		self.add_argument('--sub-tests', '-S',
				metavar='<subtests>',
				type=str, help='List of subtests to run',
				default=None, dest='sub_tests')
		self.add_argument('--result', '-e',
				type=os.path.abspath,
				help='Writes PASS/FAIL to results file')
		self.add_argument('--hw', '-w',
				type=str,
				nargs='?',
				const=True,
				action='store',
				help='Use physical adapters for tests (passthrough)')

		# Hidden options only meant to be passed to the kernel
		self.add_argument('--testhome', help=SUPPRESS)
		self.add_argument('--monitor-parent', help=SUPPRESS)
		self.add_argument('--result-parent', help=SUPPRESS)
		self.add_argument('--timeout', help=SUPPRESS)

		# Prevent --autotest/--unittest from being used together
		auto_unit_group = self.add_mutually_exclusive_group()
		auto_unit_group.add_argument('--autotests', '-A',
				metavar='<tests>',
				type=str,
				help='List of tests to run',
				default=None,
				dest='autotests')
		auto_unit_group.add_argument('--unit-tests', '-U',
				metavar='<tests>',
				type=str,
				help='List of unit tests to run',
				dest='unit_tests')

		# Prevent --valgrind/--gdb from being used together
		valgrind_gdb_group = self.add_mutually_exclusive_group()
		valgrind_gdb_group.add_argument('--gdb', '-g',
				metavar='<exec>',
				type=str,
				help='Run gdb on specified executable',
				dest='gdb')
		valgrind_gdb_group.add_argument('--valgrind', '-V',
				action='store_true',
				help='Run valgrind on IWD',
				dest='valgrind')

	# Overwrite to use a custom namespace class and parse from env
	def parse_args(self, *args):
		if len(sys.argv) > 1:
			return super().parse_args(*args, namespace=RunnerNamespace())

		options = []
		for k, v in os.environ.items():
			options.append('--' + k.replace('_', '-'))
			options.append(v)

		return self.parse_known_args(args=options, namespace=RunnerNamespace())[0]

#
# Arguments only needed outside the test environment
#
class RunnerArgParse(RunnerCoreArgParse):
	def __init__(self, *args, **kwargs):
		RunnerCoreArgParse.__init__(self, *args, **kwargs)

		self.add_argument('--runner', '-r',
				metavar='<runner type>',
				type=str,
				help='Type of runner to use (qemu, uml, host)',
				dest='runner',
				default=None)
		self.add_argument('--kernel', '-k',
				metavar='<kernel>',
				type=os.path.abspath,
				help='Path to kernel/uml image',
				dest='kernel',
				default=None)

#
# Class to sort out what type of runner this is, returns the RunnerAbstract
# implementation.
#
class Runner:
	def __new__(self):
		parser = RunnerArgParse(description='IWD Test Runner')

		args = parser.parse_args()

		# Common options
		args.PATH = os.environ['PATH']

		if 'testhome' not in args.to_cmd():
			if os.getcwd().endswith('tools'):
				args.testhome = '%s/../' % os.getcwd()
			else:
				args.testhome = os.getcwd()

		# If no runner is specified but we have a kernel image assume
		# if the kernel is executable its UML, otherwise qemu
		if not args.runner:
			if not args.kernel:
				raise Exception("Please specify --runner/--kernel")

			if os.access(args.kernel, os.X_OK):
				args.runner = 'uml'
			else:
				args.runner = 'qemu'

		if args.runner == 'uml':
			return UmlRunner(args)
		elif args.runner == 'qemu':
			return QemuRunner(args)
		else:
			raise Exception("Unknown runner %s" % args.runner)

class RunnerAbstract:
	cmdline = []
	env = None
	name = "unnamed"

	def __init__(self, args):
		self.args = args

		if len(sys.argv) <= 1:
			return

		if os.path.exists('run-tests'):
			self.init = os.path.abspath('run-tests')
		elif os.path.exists('tools/run-tests'):
			self.init = os.path.abspath('tools/run-tests')
		else:
			raise Exception("Cannot locate run-tests binary")

	def start(self):
		print("Starting %s" % self.name)
		os.execlpe(self.cmdline[0], *self.cmdline, self.env)

	def prepare_environment(self):
		path = os.environ['PATH']
		os.environ['PATH'] = '%s/src' % self.args.testhome
		os.environ['PATH'] += ':%s/tools' % self.args.testhome
		os.environ['PATH'] += ':%s/client' % self.args.testhome
		os.environ['PATH'] += ':%s/monitor' % self.args.testhome
		os.environ['PATH'] += ':%s/wired' % self.args.testhome
		os.environ['PATH'] += ':' + path

		sys.path.append(self.args.testhome + '/autotests/util')

		if not os.path.exists('/tmp/iwd'):
			os.mkdir('/tmp/iwd')

		#
		# This prevents any print() calls in this script from printing unless
		# --debug is passed. For an 'always print' option use dbg()
		#
		if not self.args.dbg:
			sys.stdout = open(os.devnull, 'w')

		# Copy autotests/misc/{certs,secrets,phonesim} so any test can refer to them
		if os.path.exists('/tmp/certs'):
			rmtree('/tmp/certs')

		if os.path.exists('/tmp/secrets'):
			rmtree('/tmp/secrets')

		copytree(self.args.testhome + '/autotests/misc/certs', '/tmp/certs')
		copytree(self.args.testhome + '/autotests/misc/secrets', '/tmp/secrets')
		copy(self.args.testhome + '/autotests/misc/phonesim/phonesim.conf', '/tmp')

		# Clear out any log files from other test runs
		if self.args.log:
			for f in [os.path.join(self.args.log, file) for file in os.listdir(self.args.log)]:
				print("removing %s" % f)

				if os.path.isdir(f):
					rmtree(f)
				else:
					os.remove(f)

		fcntl.ioctl(STDIN_FILENO, TIOCSTTY, 1)

		os.system('ip link set dev lo up')

	def cleanup_environment(self):
		rmtree('/tmp/iwd')
		rmtree('/tmp/certs')
		rmtree('/tmp/secrets')
		os.remove('/tmp/phonesim.conf')

		os.sync()

	# For QEMU/UML runners
	def _prepare_mounts(self, extra=[]):
		mounted = []

		for entry in mounts_common + extra:
			if entry.target in mounted:
				print("%s already mounted, skipping" % entry.target)
				continue

			try:
				os.lstat(entry.target)
			except:
				os.mkdir(entry.target, 755)

			mount(entry.source, entry.target, entry.fstype, entry.flags,
				entry.options)

			mounted.append(entry.target)

		for entry in dev_table:
			os.symlink(entry.target, entry.linkpath)

		os.setsid()

	# For QEMU/UML --log, --monitor, --result
	def _prepare_outfiles(self):
		append_gid_uid = False

		uid = int(os.environ.get('SUDO_UID', os.getuid()))
		gid = int(os.environ.get('SUDO_GID', os.getgid()))

		if self.args.log:
			if self.args.log == '/tmp':
				raise Exception('Log directly cannot be /tmp')

			append_gid_uid = True

			if not os.path.exists(self.args.log):
				os.mkdir(self.args.log)

			if gid:
				os.chown(self.args.log, uid, gid)

		if self.args.monitor:
			append_gid_uid = True

			self.args.monitor_parent = os.path.abspath(
						os.path.join(self.args.monitor, os.pardir))
			if self.args.monitor_parent == '/tmp':
				raise Exception('--monitor cannot be directly under /tmp')

		if self.args.result:
			append_gid_uid = True

			self.args.result_parent = os.path.abspath(
						os.path.join(self.args.result, os.pardir))
			if self.args.result_parent == '/tmp':
				raise Exception('--result cannot be directly under /tmp')

		if append_gid_uid:
			self.args.SUDO_UID = uid
			self.args.SUDO_GID = gid

	def stop(self):
		exit()

class QemuRunner(RunnerAbstract):
	name = "Qemu Runner"

	def __init__(self, args):
		def mount_options(id):
			return 'mount_tag=%s,security_model=passthrough,id=%s' % (id, id)

		usb_adapters = None
		pci_adapters = None
		ram = 256

		super().__init__(args)

		if len(sys.argv) <= 1:
			return

		if not which('qemu-system-x86_64'):
			raise Exception('Cannot locate qemu binary')

		if not args.kernel or not os.path.exists(args.kernel):
			raise Exception('Cannot locate kernel image %s' % args.kernel)

		self._prepare_outfiles()

		self.args.timeout = 240

		if args.hw:
			if os.path.isfile(args.hw):
				hw_conf = ConfigParser()
				hw_conf.read(args.hw)

				if hw_conf.has_section('USBAdapters'):
					# The actual key name of the adapter
					# doesn't matter since all we need is the
					# bus/address. This gets named by the kernel
					# anyways once in the VM.
					usb_adapters = [v for v in hw_conf['USBAdapters'].values()]

			pci_adapters = self._find_pci_adapters()

		kern_log = "ignore_loglevel" if "kernel" in args.verbose else "quiet"

		if args.valgrind:
			ram *= 2

		qemu_cmdline = [
			'qemu-system-x86_64',
			'-machine', 'type=q35,accel=kvm:tcg',
			'-nodefaults', '-no-user-config', '-monitor', 'none',
			'-display', 'none', '-m', '%dM' % ram, '-nographic', '-vga',
			'none', '-no-acpi', '-no-hpet',
			'-no-reboot', '-fsdev',
			'local,id=fsdev-root,path=/,readonly=on,security_model=none,multidevs=remap',
			'-device',
			'virtio-9p-pci,fsdev=fsdev-root,mount_tag=/dev/root',
			'-chardev', 'stdio,id=chardev-serial0,signal=off',
			'-device', 'pci-serial,chardev=chardev-serial0',
			'-device', 'virtio-rng-pci',
			'-kernel', args.kernel,
			'-smp', '2',
			'-append',
			'console=ttyS0,115200n8 earlyprintk=serial \
				rootfstype=9p root=/dev/root \
				rootflags=trans=virtio \
				acpi=off pci=noacpi %s ro \
				mac80211_hwsim.radios=0 init=%s %s' %
						(kern_log, self.init, args.to_cmd()),
		]

		# Add two ethernet devices for testing EAD
		qemu_cmdline.extend([
				'-net', 'nic,model=virtio',
				'-net', 'nic,model=virtio',
				'-net', 'user'
		])

		if usb_adapters:
			for bus, addr in [s.split(',') for s in usb_adapters]:
				qemu_cmdline.extend(['-usb',
							'-device',
							'usb-host,hostbus=%s,hostaddr=%s' % \
							(bus, addr)])
		if pci_adapters:
			qemu_cmdline.extend(['-enable-kvm'])
			for addr in pci_adapters:
				qemu_cmdline.extend(['-device', 'vfio-pci,host=%s' % addr])

		qemu_cmdline.extend([
			'-virtfs',
			'local,path=%s,%s' % (args.testhome, mount_options('homedir'))
		])

		if args.log:
			#
			# Creates a virtfs device that can be mounted. This mount
			# will point back to the provided log directory and is
			# writable unlike the rest of the mounted file system.
			#
			qemu_cmdline.extend([
				'-virtfs',
				'local,path=%s,%s' % (args.log,
							mount_options('logdir'))
			])

		if args.monitor:
			qemu_cmdline.extend([
				'-virtfs',
				'local,path=%s,%s' % (self.args.monitor_parent,
							mount_options('mondir'))
			])

		if args.result:
			qemu_cmdline.extend([
				'-virtfs',
				'local,path=%s,%s' % (self.args.result_parent,
							mount_options('resultdir'))
			])


		self.cmdline = qemu_cmdline

	def _find_pci_adapters(self):
		adapters = []

		try:
			files = os.listdir('/sys/module/vfio_pci/drivers/pci:vfio-pci')
		except:
			return None

		for bus_addr in files:
			if not bus_addr.startswith('0000:'):
				continue

			adapters.append(bus_addr.replace('0000:', ''))

		if len(adapters) == 0:
			return None

		return adapters

	def prepare_environment(self):
		mounts = [ MountInfo('debugfs', 'debugfs', '/sys/kernel/debug', '', 0) ]

		mounts.append(MountInfo('9p', 'homedir', self.args.testhome,
					'trans=virtio,version=9p2000.L,msize=10240', 0))

		if self.args.log:
			mounts.append(MountInfo('9p', 'logdir', self.args.log,
					'trans=virtio,version=9p2000.L,msize=10240', 0))

		if self.args.monitor:
			mounts.append(MountInfo('9p', 'mondir', self.args.monitor_parent,
					'trans=virtio,version=9p2000.L,msize=10240', 0))

		if self.args.result:
			mounts.append(MountInfo('9p', 'resultdir', self.args.result_parent,
					'trans=virtio,version=9p2000.L,msize=10240', 0))

		self._prepare_mounts(extra=mounts)

		super().prepare_environment()

	def stop(self):
		RB_AUTOBOOT = 0x01234567
		#
		# Killing init() results in a kernel panic. For QEMU a graceful
		# exit is achieved with RB_AUTOBOOT
		#
		libc.reboot(RB_AUTOBOOT)

class UmlRunner(RunnerAbstract):
	name = "UML Runner"

	def __init__(self, args):
		super().__init__(args)

		if len(sys.argv) <= 1:
			return

		if not which(args.kernel):
			raise Exception('Cannot locate UML binary %s' % args.kernel)

		self._prepare_outfiles()

		self.args.timeout = 1000

		kern_log = "ignore_loglevel" if "kernel" in args.verbose else "quiet"

		if self.args.valgrind:
			ram = 512
		else:
			ram = 256

		cmd = [args.kernel, 'rootfstype=hostfs', 'ro', f'mem={ram}M', 'mac80211_hwsim.radios=0',
				'time-travel=inf-cpu', 'eth0=mcast', 'eth1=mcast',
				'%s' % kern_log, 'init=%s' % self.init]
		cmd.extend(args.to_cmd().split(' '))

		self.cmdline = cmd

	def prepare_environment(self):
		mounts = []

		if self.args.log:
			mounts.append(MountInfo('hostfs', 'hostfs', self.args.log,
						self.args.log, 0))

		if self.args.monitor:
			mounts.append(MountInfo('hostfs', 'hostfs', self.args.monitor_parent,
						self.args.monitor_parent, 0))

		if self.args.result:
			mounts.append(MountInfo('hostfs', 'hostfs', self.args.result_parent,
						self.args.result_parent, 0))

		mounts.append(MountInfo('hostfs', 'hostfs', self.args.testhome,
					self.args.testhome, 0))

		self._prepare_mounts(extra=mounts)

		super().prepare_environment()

	def stop(self):
		RB_POWER_OFF = 0x4321fedc
		#
		# Killing init() results in a kernel panic. For UML a graceful
		# exit is achieved with RB_POWER_OFF
		#
		libc.reboot(RB_POWER_OFF)
