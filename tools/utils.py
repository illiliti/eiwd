import os
import subprocess
import fcntl
import sys
import traceback
import shutil
import dbus

from gi.repository import GLib
from weakref import WeakValueDictionary
from re import fullmatch
from time import sleep

from runner import RunnerCoreArgParse

class Process(subprocess.Popen):
	processes = WeakValueDictionary()
	testargs = RunnerCoreArgParse().parse_args()

	def __new__(cls, *args, **kwargs):
		obj = super().__new__(cls)
		cls.processes[id(obj)] = obj
		return obj

	def __init__(self, args, namespace=None, outfile=None, env=None, check=False, cleanup=None):
		self.write_fds = []
		self.io_watch = None
		self.cleanup = cleanup
		self.verbose = False
		self.out = ''
		self.hup = False
		self.killed = False
		self.namespace = namespace

		logfile = args[0]

		if Process.is_verbose(args[0], log=False):
			self.verbose = True

		if namespace:
			args = ['ip', 'netns', 'exec', namespace] + args
			logfile += '-%s' % namespace

		if outfile:
			# outfile is only used by iwmon, in which case we don't want
			# to append to an existing file.
			self._append_outfile(outfile, append=False)

		if self.testargs.log:
			testdir = os.getcwd()

			# Special case any processes started prior to a test
			# (i.e. from testhome). Put these in the root log directory
			if testdir == self.testargs.testhome:
				testdir = '.'
			else:
				testdir = os.path.basename(testdir)

			logfile = '%s/%s/%s' % (self.testargs.log, testdir, logfile)
			self._append_outfile(logfile)

		super().__init__(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
					env=env, cwd=os.getcwd())

		# Set as non-blocking so read() in the IO callback doesn't block forever
		fl = fcntl.fcntl(self.stdout, fcntl.F_GETFL)
		fcntl.fcntl(self.stdout, fcntl.F_SETFL, fl | os.O_NONBLOCK)

		self.io_watch = GLib.io_add_watch(self.stdout, GLib.IO_IN |
						GLib.IO_HUP | GLib.IO_ERR, self.process_io)

		print("Starting process {}".format(self.args))

		if check:
			self.wait(10)
			self.killed = True
			if self.returncode != 0:
				raise subprocess.CalledProcessError(returncode=self.returncode,
									cmd=args)

	@staticmethod
	def is_verbose(process, log=True):
		exclude = ['iwd-rtnl']
		process = os.path.basename(process)

		if Process.testargs is None:
			return False

		# every process is verbose when logging is enabled
		if log and Process.testargs.log and process not in exclude:
			return True

		if process in Process.testargs.verbose:
			return True

		# Special case here to enable verbose output with valgrind running
		if process == 'valgrind' and 'iwd' in Process.testargs.verbose:
			return True

		# Handle any regex matches
		for item in Process.testargs.verbose:
			try:
				if fullmatch(item, process):
					return True
			except Exception as e:
				print("%s is not a valid regex" % item)

		return False

	@classmethod
	def get_all(cls):
		return cls.processes.values()

	@classmethod
	def kill_all(cls):
		for p in cls.processes.values():
			if p.args[0] == 'dmesg':
				continue

			p.kill()

	@staticmethod
	def _write_io(instance, data, stdout=True):
		for f in instance.write_fds:
			f.write(data)

			# Write out a separator so multiple process calls per
			# test are easer to read.
			if instance.hup:
				f.write("Terminated: {}\n\n".format(instance.args))

			f.flush()

		if instance.verbose and stdout:
			sys.__stdout__.write(data)
			sys.__stdout__.flush()

	@classmethod
	def write_separators(cls, test, sep):
		#
		# There are either log running processes (cls.processes) or
		# processes that have terminated already but a log file exists
		# on disk. We still want the separators to show for both cases
		# so after writing separators for running processes, also
		# write them in any additional log files.
		#
		nowrite = []

		for proc in cls.processes.values():
			if proc.killed:
				continue

			cls._write_io(proc, sep, stdout=False)
			nowrite.append(proc.args[0])

		if cls.testargs.log:
			logfiles = os.listdir('%s/%s' % (cls.testargs.log, test))

			extra = list(set(logfiles) - set(nowrite))

			for log in extra:
				logfile = '%s/%s/%s' % (cls.testargs.log, test, log)
				with open(logfile, 'a') as f:
					f.write(sep)
				f.close()

	def process_io(self, source, condition):
		if condition & GLib.IO_HUP:
			self.hup = True

		data = source.read()

		if not data:
			return True

		try:
			data = data.decode('utf-8')
		except:
			return True

		# Save data away in case the caller needs it (e.g. list_sta)
		self.out += data

		self._write_io(self, data)

		return True

	def _append_outfile(self, file, append=True):
		gid = int(os.environ.get('SUDO_GID', os.getgid()))
		uid = int(os.environ.get('SUDO_UID', os.getuid()))
		dir = os.path.dirname(file)

		if not os.path.exists(dir):
			os.mkdir(dir)
			os.chown(dir, uid, gid)

		file = os.path.join(dir,file)

		# If the out file exists, append. Useful for processes like
		# hostapd_cli where it is called multiple times independently.
		if os.path.isfile(file) and append:
			mode = 'a'
		else:
			mode = 'w'

		try:
			f = open(file, mode)
		except Exception as e:
			traceback.print_exc()
			sys.exit(0)

		os.fchown(f.fileno(), uid, gid)

		self.write_fds.append(f)

	def wait_for_socket(self, socket, wait):
		def _wait(socket):
			if not os.path.exists(socket):
				sleep(0.1)
				return False
			return True

		Namespace.non_block_wait(_wait, wait, socket,
				exception=Exception("Timed out waiting for %s" % socket))

	def wait_for_service(self, ns, service, wait):
		def _wait(ns, service):
			if not ns._bus.name_has_owner(service):
				sleep(0.1)
				return False
			return True

		Namespace.non_block_wait(_wait, wait, ns, service,
				exception=Exception("Timed out waiting for %s" % service))

	# Wait for both process termination and HUP signal
	def __wait(self, timeout):
		try:
			super().wait(timeout)
			if not self.hup:
				return False

			return True
		except:
			return False

	# Override wait() so it can do so non-blocking
	def wait(self, timeout=10):
		if timeout == None:
			super().wait()
			return

		Namespace.non_block_wait(self.__wait, timeout, 1)
		self._cleanup()

	def _cleanup(self):
		if self.cleanup:
			self.cleanup()

		self.write_fds = []

		if self.io_watch:
			GLib.source_remove(self.io_watch)
			self.io_watch = None

		self.cleanup = None
		self.killed = True

	# Override kill()
	def kill(self, force=False):
		if self.killed:
			return

		print("Killing process {}".format(self.args))

		if force:
			super().kill()
		else:
			self.terminate()

		try:
			self.wait(timeout=15)
		except:
			print("Process %s did not complete in 15 seconds!" % self.args[0])
			super().kill()

		self._cleanup()

	def __str__(self):
		return str(self.args) + '\n'

dbus_count = 0
# Partial DBus config. The remainder (<listen>) will be filled in for each
# namespace that is created so each individual dbus-daemon has its own socket
# and address.
dbus_config = '''
<!DOCTYPE busconfig PUBLIC \
"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" \
"http://www.freedesktop.org/standards/dbus/1.0/\
busconfig.dtd\">
<busconfig>
<type>system</type>
<limit name=\"reply_timeout\">2147483647</limit>
<auth>ANONYMOUS</auth>
<allow_anonymous/>
<policy context=\"default\">
<allow user=\"*\"/>
<allow own=\"*\"/>
<allow send_type=\"method_call\"/>
<allow send_type=\"signal\"/>
<allow send_type=\"method_return\"/>
<allow send_type=\"error\"/>
<allow receive_type=\"method_call\"/>
<allow receive_type=\"signal\"/>
<allow receive_type=\"method_return\"/>
<allow receive_type=\"error\"/>
<allow send_destination=\"*\" eavesdrop=\"true\"/>
<allow eavesdrop=\"true\"/>
</policy>
'''

class Namespace:
	def __init__(self, args, name, radios):
		self.dbus_address = None
		self.name = name
		self.radios = radios
		self.args = args

		Process(['ip', 'netns', 'add', name]).wait()
		for r in radios:
			r.set_namespace(self)

		self.start_dbus()

	def reset(self):
		self._bus = None

		for r in self.radios:
			r._radio = None

		self.radios = []

		Process.kill_all()

	def __del__(self):
		if self.name:
			print("Removing namespace %s" % self.name)

			Process(['ip', 'netns', 'del', self.name]).wait()

	def get_bus(self):
		return self._bus

	def start_process(self, args, env=None, **kwargs):
		if not env:
			env = os.environ.copy()

		if hasattr(self, "dbus_address"):
			# In case this process needs DBus...
			env['DBUS_SYSTEM_BUS_ADDRESS'] = self.dbus_address

		return Process(args, namespace=self.name, env=env, **kwargs)

	def stop_process(self, p, force=False):
		p.kill(force)

	def _is_running(self, pid):
		try:
			os.kill(pid, 0)
		except OSError:
			return False

		return True

	def is_process_running(self, process):
		for p in Process.get_all():
			# Namespace processes are actually started by 'ip' where
			# the actual process name is at index 4 of the arguments.
			idx = 0 if not p.namespace else 4

			if p.namespace == self.name and p.args[idx] == process:
				# The process object exists, but make sure its
				# actually running.
				return self._is_running(p.pid)
		return False

	def _cleanup_dbus(self):
		try:
			os.remove(self.dbus_address.split('=')[1])
		except:
			pass

		os.remove(self.dbus_cfg)

	def start_dbus(self):
		global dbus_count

		self.dbus_address = 'unix:path=/tmp/dbus%d' % dbus_count
		self.dbus_cfg = '/tmp/dbus%d.conf' % dbus_count
		dbus_count += 1

		with open(self.dbus_cfg, 'w+') as f:
			f.write(dbus_config)
			f.write('<listen>%s</listen>\n' % self.dbus_address)
			f.write('</busconfig>\n')

		p = self.start_process(['dbus-daemon', '--config-file=%s' % self.dbus_cfg],
					cleanup=self._cleanup_dbus)

		p.wait_for_socket(self.dbus_address.split('=')[1], 5)

		self._bus = dbus.bus.BusConnection(address_or_type=self.dbus_address)

	def start_iwd(self, config_dir = '/tmp', storage_dir = '/tmp/iwd',
				developer_mode = True):
		args = []
		iwd_radios = ','.join([r.name for r in self.radios if r.use == 'iwd'])

		if self.args.valgrind:
			args.extend(['valgrind', '--leak-check=full', '--track-origins=yes',
					'--show-leak-kinds=all',
					'--log-file=/tmp/valgrind.log.%p'])

		args.append('iwd')

		if developer_mode:
			args.append('-E')

		if iwd_radios != '':
			args.extend(['-p', iwd_radios])

		if Process.is_verbose(args[0]):
			args.append('-d')

		env = os.environ.copy()

		env['CONFIGURATION_DIRECTORY'] = config_dir
		env['STATE_DIRECTORY'] = storage_dir

		if Process.is_verbose('iwd-dhcp'):
			env['IWD_DHCP_DEBUG'] = '1'

		if Process.is_verbose('iwd-tls'):
			env['IWD_TLS_DEBUG'] = '1'

		if Process.is_verbose('iwd-acd'):
			env['IWD_ACD_DEBUG'] = '1'

		if Process.is_verbose('iwd-rtnl'):
			env['IWD_RTNL_DEBUG'] = '1'

		if Process.is_verbose('iwd-sae'):
			env['IWD_SAE_DEBUG'] = '1'

		proc = self.start_process(args, env=env)

		proc.wait_for_service(self, 'net.connman.iwd', 20)

		return proc

	@staticmethod
	def non_block_wait(func, timeout, *args, exception=True):
		'''
			Convenience function for waiting in a non blocking
			manor using GLibs context iteration i.e. does not block
			the main loop while waiting.

			'func' will be called at least once and repeatedly until
			either it returns success, throws an exception, or the
			'timeout' expires.

			'timeout' is the ultimate timeout in seconds

			'*args' will be passed to 'func'

			If 'exception' is an Exception type it will be raised.
			If 'exception' is True a generic TimeoutError will be raised.
			Any other value will not result in an exception.
		'''
		# Simple class for signaling the wait timeout
		class Bool:
			def __init__(self, value):
				self.value = value

		def wait_timeout_cb(done):
			done.value = True
			return False

		mainloop = GLib.MainLoop()
		done = Bool(False)

		timeout = GLib.timeout_add_seconds(timeout, wait_timeout_cb, done)
		context = mainloop.get_context()

		while True:
			try:
				ret = func(*args)
				if ret:
					if not done.value:
						GLib.source_remove(timeout)
					return ret
			except Exception as e:
				if not done.value:
					GLib.source_remove(timeout)
				raise e

			if done.value == True:
				if isinstance(exception, Exception):
					raise exception
				elif type(exception) == bool and exception:
					raise TimeoutError("Timeout on non_block_wait")
				else:
					return

			context.iteration(may_block=True)

	def __str__(self):
		ret = 'Namespace: %s\n' % self.name
		ret += 'Processes:\n'
		for p in Process.get_all():
			ret += '\t%s' % str(p)

		ret += 'Radios:\n'
		if len(self.radios) > 0:
			for r in self.radios:
				ret += '\t%s\n' % str(r)
		else:
			ret += '\tNo Radios\n'

		ret += 'DBus Address: %s\n' % self.dbus_address
		ret += '===================================================\n\n'

		return ret

class BarChart():
	def __init__(self, height=10, max_width=80):
		self._height = height
		self._max_width = max_width
		self._values = []
		self._max_value = 0
		self._min_value = 0

	def add_value(self, value):
		if len(self._values) == 0:
			self._max_value = int(1.01 * value)
			self._min_value = int(0.99 * value)
		elif value > self._max_value:
			self._max_value = int(1.01 * value)
		elif value < self._min_value:
			self._min_value = int(0.99 * value)

		self._values.append(value)

	def _value_to_stars(self, value):
		# Need to scale value (range of min_value -> max_value) to
		# a range of 0 -> height
		#
		# Scaled = ((value - min_value) / ( max_value - min_value)) * (Height - 0) + 0

		return int(((value - self._min_value) /
			(self._max_value - self._min_value)) * self._height)

	def __str__(self):
		# Need to map value from range 0 - self._height
		ret = ''

		for i, value in enumerate(self._values):
			stars = self._value_to_stars(value)
			ret += '[%3u] ' % i + '%-10s' % ('*' * stars) + '\t\t\t%d\n' % value

		ret += '\n'

		return ret
