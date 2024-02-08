#!/usr/bin/env python
# Author: Tobi Vollebregt
# Thanks to bibim for providing the perl source of his translator.
# requires mingw32-binutils and p7zip to work

import os, re, sys
import logging
import traceback
from tempfile import NamedTemporaryFile
from subprocess import Popen, PIPE, TimeoutExpired
import time
import pefile
from update_debug_symbols import get_for_engineversion

# documentation
# 1. get an infolog.txt
# 2. Collect the following info from it:
#	2.1 Engine Version
#	2.2 Module (dll) offset Addresses
#	2.3 Stack Trace is
# 3. Figure out if we have that debug file on hand
# 4. Try to download that debug file if not
#	4.1. Unzip the downloaded debug file, and only keep the spring.dbg file, and the dll for Barb

# Paths to required helper programs.
#ADDR2LINE = r'/usr/bin/i686-w64-mingw32-addr2line'

ADDR2LINE = r'/usr/bin/addr2line'
SEVENZIP = r'/usr/bin/7za'

# Everything before the first occurence of this is stripped
# from paths returned by addr2line.
# First one is buildbot, second one is BuildServ.
PATH_STRIP_UNTIL = ['/build/', '}.mingw32.cmake/']

# Root of the directory tree with debugging symbols.
# Must contain paths of the form config/branch/rev/...
WWWROOT = os.path.expanduser('~/www/www/bar/stacktrace_translator')
# if this path does not exist, that means we are running in docker, and should just handle everything locally.
if not os.path.exists(WWWROOT):
	WWWROOT = "."

# Where to put the log & pid file when running as server.
#LOGFILE = os.path.expanduser('~/log/stacktrace_translator.log')   # unused currently
PIDFILE = os.path.expanduser(os.path.join(WWWROOT, 'stacktrace_translator.pid'))

# Object passed into the XMLRPC server object to listen on.
LISTEN_ADDR = ('', 8000)

# path to test file
TESTFILE = os.path.join(WWWROOT, "default/release/93.2.1-56-gdca244e/win32/{release}93.2.1-56-gdca244e_spring_dbg.7z")

# Match common pre- and suffix on infolog lines
# This is the common prefix:  [t=00:25:33.861200][f=0024446]
# This also allows
# "empty" prefixes followed by any amount of trailing whitespace.
# the a-zA-Z class can be "Warning" or "Error"

# the RE_PREFIX matches for [t=00:02:17.777911][f=-0000304]
RE_PREFIX = r'^((\[t=([0-9:\.])*\])?(?:\[(?:f=)?\s*\-?\d+\]\s*)?(?:[a-zA-Z]+:)?).*\s*' # teifion says this is good for f=-00

# This matches for end of line type stuff, independent of system info.
RE_SUFFIX = r'(?:[\r\n]+$)?'

# Match stackframe lines, captures the module name and the address.
# Example: '[0] (0) C:\Program Files\Spring\spring.exe [0x0080F268]'
#          -> ('C:\\Program Files\\Spring\\spring.exe', '0x0080F268')
# NOTE: does not match format of stackframe lines on Linux!
#[t=00:02:04.492434][f=0000536] Error: 	(0) C:\Users\xxx\Documents\My Games\Spring\engine\spring_bar_{BAR}104.0.1-1695-gbd6b256_windows-64-minimal-portable\spring.exe [0x004DD130]
#Spring 104.0.1-1695-gbd6b256 BAR

# [t=00:00:00.695000] Error: Spring 105.1.1-861-ge8bf8a9 BAR105 has crashed. 
# is buggy

#[t=00:02:17.958926][f=0000304] Error: 0x00007ff64baf0000	spring
RE_EXEBASE = RE_PREFIX + r'(0x[0-9a-f]{8,16})\s+spring' + RE_SUFFIX
EXEBASE = 0

#[t=00:02:17.962610][f=0000304] Error: 	(14) D:\Program Files\Beyond-All-Reason\data\engine\105.1.1-2127-g9568247 bar\spring.exe [0x00007ff64c3283a7]
RE_STACKFRAME = RE_PREFIX + r'\(\d+\)\s+(.*(?:\.exe|\.dll))(?:\([^)]*\))?\s+\[(0x[\dA-Fa-f]+)\]' + RE_SUFFIX
## regex for RC12 versions: first two parts are
## mandatory, last two form one optional group
RE_VERSION_NAME_PREFIX = "(Error:)? ?(?:[sS]pring)"
RE_VERSION_STRING_RC12 = "([0-9]+\.[0-9]+[\.0-9]*(?:-[0-9]+-g[0-9a-f]+)?)"
RE_VERSION_BRANCH_NAME = "([a-zA-Z0-9\-]+)?"
RE_VERSION_BUILD_FLAGS = "?(?:\s*\((?:[a-zA-Z0-9\-]+\)))?"
RE_VERSION =                        \
	RE_VERSION_NAME_PREFIX + " ?" + \
	RE_VERSION_STRING_RC12 + " ?" + \
	RE_VERSION_BRANCH_NAME + " ?" + \
	RE_VERSION_BUILD_FLAGS
# RE_PREFIX +
RE_MODULE_OFFSET = r'^(\[t=([0-9:\.])*\])?(?:\[(?:f=)?\s*\-?\d+\]\s*)? Error: (0x[a-fA-F0-9]+)\t([a-zA-Z0-9\-]+)' + RE_SUFFIX

# Match complete line containing version string.
# NOTE:
#   these are highly sensitive to changes in format
#   strings passed to LOG(), perhaps define them in
#   a header and parse that?
RE_VERSION_LINES = [
	x % (RE_PREFIX, RE_VERSION, RE_SUFFIX) for x in [
		r'%sStacktrace for %s:%s', # [t=00:02:35.214753][f=-000001] Error: Stacktrace for Spring 105.1.1-1354-g72b2d55 BAR105:
		r'%sStacktrace \([a-zA-Z0-9 ]+\) for %s:%s',

		## legacy version patterns
		r'%s%s has crashed\.%s', # [t=00:25:33.861200][f=0024446] Error: Spring 105.1.1-1354-g72b2d55 BAR105 has crashed.
		r'%s Error handler invoked for %s\.%s', # [t=01:53:30.145423][f=-000001] Error: Error handler invoked for Spring 105.1.1-1354-g72b2d55 BAR105.
		r'%s\[Watchdog\] Hang detection triggered for %s\.%s',
		r'%sSegmentation fault \(SIGSEGV\) in %s%s',
		r'%sAborted \(SIGABRT\) in %s%s',
		r'%sError handler invoked for %s\.%s', # [t=00:02:35.092580][f=-000001] Error: Error handler invoked for Spring 105.1.1-1354-g72b2d55 BAR105.
	]
]

#[t=00:02:04.350819][f=0000536] Error: Spring 104.0.1-1695-gbd6b256 BAR has crashed.
#Actual engine path: engine\spring_bar_{BAR}104.0.1-1695-gbd6b256_windows-64-minimal-portable\
#[t=00:02:04.492434][f=0000536] Error: 	(0) C:\Users\psarkozy\Documents\My Games\Spring\engine\spring_bar_{BAR}104.0.1-1695-gbd6b256_windows-64-minimal-portable\spring.exe [0x004DD130] 

# Capture config, branch, rev from `Additional' version string.
#RE_CONFIG = r'(?:\[(?P<config>[^\]]+)\])?'
#RE_BRANCH = r'(?:\{(?P<branch>[^\}]+)\})?'
#RE_REV = r'(?P<rev>[0-9.]+(?:-[0-9]+-g[0-9A-Fa-f]+)?)'
#RE_VERSION_DETAILS = re.compile(RE_CONFIG + RE_BRANCH + RE_REV + r'\s')

# Match filename of file with debugging symbols, capture module name.
RE_DEBUG_FILENAME = '.*spring_dbg.7z' #old
#RE_DEBUG_FILENAME = '.*spring.*.tgz.7z' #new one needs unzippingm




def test_version(string):
	'''
		>>> test_version('Spring 91.0 (OMP)')
		('91.0', None)

		>>> test_version('spring 93.2.1-82-g863e91e release (Debug OMP)')
		('93.2.1-82-g863e91e', 'release')
	'''
	log.debug('test_version():'+string)
	return re.search(RE_VERSION, string, re.MULTILINE).groups()

# Set up application log.
logging.basicConfig(level = logging.DEBUG, handlers = [logging.StreamHandler(), logging.FileHandler(f'log_stacktrace_translator_{time.strftime("%Y%m%d-%H%M%S")}.txt')])
log = logging.getLogger(' ')
log.setLevel(logging.DEBUG)


class FatalError(Exception):
	'''The only exception that doesn't trigger a dump of a trace server-side.'''
	def __init__(self, message):
		Exception.__init__(self, message)


def fatal(message):
	'''A fatal error happened, quit the translation process.'''
	log.error(message)   # for server
	raise FatalError(message)   # for client


def best_matching_module(needle, haystack): # a module is a .exe or a .dll
	'''\
	Choose the best matching module, based on longest common suffix.

	This way it ignores the install location of Spring:

		>>> modules = ['spring.exe', 'AI/Skirmish/NullAI/SkirmishAI.dll']
		>>> best_matching_module('c:/Program Files/Spring/spring.exe', modules)
		'spring.exe'
		>>> best_matching_module('c:/Spring/NullAI/0.0.1/SkirmishAI.dll', modules)
		'AI/Skirmish/NullAI/SkirmishAI.dll'

	If the correct module isn't available nothing is returned:

		>>> best_matching_module('c:/Program Files/Spring/AI/Skirmish/UnknownAI/0.0.1/SkirmishAI.dll', modules)
	'''
	parts = needle.replace('\\', '/').split('/')
	if parts[-1] == 'SkirmishAI.dll':
		needle = '%s/SkirmishAI.dll' % parts[-3]
	else:
		needle = parts[-1]
	log.debug("parts %s", str(parts))
	log.debug("haystack %s", str(haystack))
	if needle == 'BARb/SkirmishAI.dll' :
		needle = 'BARb/stable/SkirmishAI.dbg/SkirmishAI.dll' 

	log.debug('best_matching_module: looking for %s', needle)
	for module in haystack:
		if module.endswith(needle):
			log.debug('best_matching_module: found %s', module)
			return module
	log.debug('best_matching_module: module not found')
	return None


def detect_version_details(infolog):
	'''\
	Detect config, branch, rev from version string(s) in infolog.

	These should be fine:

		>>> detect_version_details('Segmentation fault (SIGSEGV) in spring 91.0 (OMP)')
		('default', 'master', '91.0')

		>>> detect_version_details('Segmentation fault (SIGSEGV) in spring 93.2.1-82-g863e91e release (Debug OMP)')
		('default', 'release', '93.2.1-82-g863e91e')

		>>> detect_version_details('Spring 93.2.1-56-gdca244e release (OMP) has crashed.')
		('default', 'release', '93.2.1-56-gdca244e')

	This is an old-style (BuildServ) version string, it should be rejected:

		>>> detect_version_details('Spring 0.81.2.1 (0.81.2.1-0-g884a107{@}-cmake-mingw32) has crashed.')
		Traceback (most recent call last):
			...
		FatalError: Unable to find detailed version in infolog
	'''
	version = None
	branch = None
	for re_version_line in RE_VERSION_LINES:
		match = re.search(re_version_line, infolog, re.MULTILINE)
		print ("Trying regex", re_version_line)
		if match:
			print ("RE_VERSION_LINES match.groups:",match.groups())
			version = match.groups()[-1]
			branch = match.groups()[-2]
			break
	else:
		fatal('Unable to find detailed version in infolog'+ str(re_version_line) + str(match))
	if not branch: branch = 'master'
	# FIXME: config support (how does a version string with config currently look like?!)
	print ("Version details that have been detected are: branch=%s, version=%s"%(branch,version))
	return 'default', branch, version


def collect_stackframes(infolog):
	'''\
	Collect stackframes from infolog, grouped by module.
	(because addr2line has a huge per-module overhead)

		>>> collect_stackframes('(0) C:/spring.exe [0x0080F268]')
		({'C:/spring.exe': [(0, '0x0080F268')]}, 1)

		>>> collect_stackframes('[f=0000000] Error: (7) C:/Spring93.2.1-56/spring.exe [0x0061276A]')
		({'C:/Spring93.2.1-56/spring.exe': [(0, '0x0061276A')]}, 1)
	'''
	log.info('Collecting stackframes per module...')

	frames = {}
	frame_count = 0
	#for module, address in re.findall(RE_STACKFRAME, infolog, re.MULTILINE):
	for rematch in re.findall(RE_STACKFRAME, infolog, re.MULTILINE):
		print(rematch)
		address = rematch[-1]
		module = rematch[-2]
		frames.setdefault(module, []).append((frame_count, address))
		frame_count += 1

	log.debug('frames = %s, frame_count = %d', frames, frame_count)
	log.info('\t[OK]')
	return frames, frame_count


def get_module_offsets(infolog):
	'''
	'''
	log.info('Collecting getting module offsets...' + RE_MODULE_OFFSET)
	module_offsets = {} # matches module name to hex offset
	
	#for module, address in re.findall(RE_STACKFRAME, infolog, re.MULTILINE):
	for rematch in re.findall(RE_MODULE_OFFSET, infolog, re.MULTILINE):
		print(rematch)
		address = rematch[-2]
		module = rematch[-1]
		module_offsets[module] = address
		
	#[t=01:12:42.524104][f=0006608] Error: Exception Address: 0x00007ff785cc54d0
	for rematch in re.findall(r'^(\[t=([0-9:\.])*\])?(?:\[(?:f=)?\s*\-?\d+\]\s*)? Error: Exception Address: (0x[a-fA-F0-9]+)' + RE_SUFFIX, infolog, re.MULTILINE):
		print ("Found Error: Exception Address:", rematch[-1])
		if "spring" in module_offsets:
			module_offsets["spring"] = rematch[-1][0:10] + module_offsets["spring"][-8:]
			print ("replacing module offset with :", module_offsets["spring"])
	log.debug('Got module offsets: %s', str(module_offsets))
	log.info('\t[OK]')
	return module_offsets
#btw the correct formula is 
#  (exception address & 0xFFFFFFFF -  0x00000000858b0000    (module addresss)) + 0x1400000000 


def get_modules(dbgfile):
	'''
	returns a list of all available files in a 7z archive
		>>> get_modules(TESTFILE)
		['AI/Interfaces/C/0.1/AIInterface.dbg', 'AI/Interfaces/Java/0.1/AIInterface.dbg', 'AI/Skirmish/AAI/0.9/SkirmishAI.dbg', 'AI/Skirmish/CppTestAI/0.1/SkirmishAI.dbg', 'AI/Skirmish/E323AI/3.25.0/SkirmishAI.dbg', 'AI/Skirmish/KAIK/0.13/SkirmishAI.dbg', 'AI/Skirmish/NullAI/0.1/SkirmishAI.dbg', 'AI/Skirmish/RAI/0.601/SkirmishAI.dbg', 'AI/Skirmish/Shard/dev/SkirmishAI.dbg', 'spring.dbg', 'springserver.dbg', 'unitsync.dbg']
	'''
	sevenzip = Popen([SEVENZIP, 'l', dbgfile], stdout = PIPE, stderr = PIPE)
	stdout, stderr = sevenzip.communicate()
	if stderr:
		log.debug('%s stderr: %s' % (SEVENZIP, stderr))
	if sevenzip.returncode != 0:
		fatal('%s exited with status %s' % (SEVENZIP, sevenzip.returncode))

	files = []
	for line in stdout.decode("utf-8").splitlines():
		match = re.match("^.* ([a-zA-Z\/0-9\.]+dbg)$", line)
		if match:
			files.append(match.group(1))
	return files


def collect_modules(config, branch, rev, platform, dbgsymdir = None):
	'''\
	Collect modules for which debug data is available.
	Return dict which maps (simplified) module name to debug symbol filename.
		>>> collect_modules('default', 'release', '93.2.1-56-gdca244e', 'win32')
		{'Java/AIInterface.dll': 'AI/Interfaces/Java/0.1/AIInterface.dbg', 'unitsync.dll': 'unitsync.dbg', 'spring.exe': 'spring.dbg', 'CppTestAI': 'AI/Skirmish/CppTestAI/0.1/SkirmishAI.dbg/SkirmishAI.dll', 'E323AI': 'AI/Skirmish/E323AI/3.25.0/SkirmishAI.dbg/SkirmishAI.dll', 'AAI': 'AI/Skirmish/AAI/0.9/SkirmishAI.dbg/SkirmishAI.dll', 'Shard': 'AI/Skirmish/Shard/dev/SkirmishAI.dbg/SkirmishAI.dll', 'RAI': 'AI/Skirmish/RAI/0.601/SkirmishAI.dbg/SkirmishAI.dll', 'C/AIInterface.dll': 'AI/Interfaces/C/0.1/AIInterface.dbg', 'KAIK': 'AI/Skirmish/KAIK/0.13/SkirmishAI.dbg/SkirmishAI.dll', 'NullAI': 'AI/Skirmish/NullAI/0.1/SkirmishAI.dbg/SkirmishAI.dll'}
	'''
	log.info('Checking debug data availability...')

	if (dbgsymdir == None):
		log.info(f'No dbgsymdir specified, using {WWWROOT}/{config}/{branch}/{rev}/{platform}')
		dbgsymdir = os.path.join(WWWROOT, config, branch, rev, platform)

	log.debug(f'Using dir {dbgsymdir}')

	if not os.path.isdir(dbgsymdir):
		log.info(f"Debug symbol directory {dbgsymdir} does not exist.")
		try:
			log.info(f"Attempting to download debug symbols for {branch}")
			get_for_engineversion(branch) #expects 105.1.1-2127-g9568247
		except:

			fatal('No debugging symbols available, \"%s\" not a directory' % dbgsymdir)
		# attempt to get the one via update_debug_symbols.py!


	dbgfile = None

	for filename in os.listdir(dbgsymdir):
		log.debug(f"Is {filename} a dbg file?")
		match = re.match(RE_DEBUG_FILENAME, filename)
		if match:
			dbgfile = os.path.join(dbgsymdir, filename)

	if not dbgfile:
		return None, None

	archivefiles = get_modules(dbgfile)
	modules = {}

	for module in archivefiles:
		if module == 'spring.dbg':
			modules["spring.exe"] = module
		elif module == 'unitsync.dbg':
			modules["unitsync.dll"] = module
		elif module.startswith('AI/Interfaces'):
			name = module.split('/')[2] + '/AIInterface.dll'
			modules[name] = module
		elif module.startswith('AI/Skirmish'):
			name = module.split('/')[2]
			modules[module + '/SkirmishAI.dll'] = module
		else:
			log.error("no match found: "+module)
	log.info('\t[OK]')
	return dbgfile, modules

def detect_exebase(infolog):
	match = re.search(RE_EXEBASE, infolog, re.MULTILINE)
	global EXEBASE
	EXEBASE = int(match.group(4), 16) if match else 0
	log.info("EXEBASE is identified as: "+str(match))

def update_base(module, addresses, tempfile):
	pe = pefile.PE(name=tempfile.name, fast_load=True)
	image_base = pe.OPTIONAL_HEADER.ImageBase
	load_base = 0 if module.endswith('.dll') else EXEBASE
	return [hex(int(x, 16) - load_base + image_base) for x in addresses]


def translate_module_addresses(module, debugarchive, addresses, debugfile, offset):
	# note that debugfile is the .7z file, and debugarchive is the .dbg
	'''\
	Translate addresses in a module to (module, address, filename, lineno) tuples
	by invoking addr2line exactly once on the debugging symbols for that module.
		>>> translate_module_addresses( 'spring.dbg', TESTFILE, ['0x0'])
		[('spring.dbg', '0x0', '??', 0)]
	'''
	
	# lets quickly check if it already exists!
	log.info('Checking if target archive is already extracted: module = %s, debugarchive = %s, debugfile = %s' % (module, debugarchive, debugfile))
	dirname, fname = os.path.split(debugfile)
	fileAlreadyExists = False
	if debugarchive == "spring.dbg":
		if os.path.exists(os.path.join(dirname, debugarchive)):
			log.info("found %s"%(os.path.join(dirname, debugarchive)))
			fileAlreadyExists = True
		else:
			log.info("not found %s, extracting %s "%(os.path.join(dirname, debugfile),debugarchive))
			# we should extract the archive. The only problem here being the paths to multiple SkirmishAI.dbg files!
			if os.path.exists(os.path.join(dirname, debugfile)):
				sevenzip = Popen([SEVENZIP, 'e', '-y', debugfile, debugarchive], stdout = PIPE, stderr = PIPE)
				stdout, stderr = sevenzip.communicate()
				if stderr:
					log.debug('%s stderr: %s' % (SEVENZIP, stderr))
				if sevenzip.returncode != 0:
					fatal('%s exited with status %s' % (SEVENZIP, sevenzip.returncode))
				fileAlreadyExists = True
				
			
	
	with (open(os.path.join(dirname, debugarchive)) if fileAlreadyExists else NamedTemporaryFile()) as tempfile:
		if not fileAlreadyExists:
			log.info('\tExtracting debug symbols for module %s from archive %s...' % (module, os.path.basename(debugfile)))
			# e = extract without path, -so = write output to stdout, -y = yes to all questions
			sevenzip = Popen([SEVENZIP, 'e', '-so', '-y', debugfile, debugarchive], stdout = tempfile, stderr = PIPE)
			stdout, stderr = sevenzip.communicate()
			if stderr:
				log.debug('%s stderr: %s' % (SEVENZIP, stderr))
			if sevenzip.returncode != 0:
				fatal('%s exited with status %s' % (SEVENZIP, sevenzip.returncode))
			log.info('\t\t[OK]')
			log.info(str(stdout))
		log.info('\tTranslating addresses for module %s...' % module)
		if module.endswith('.dll'):
			cmd = [ADDR2LINE, '-j', '.text', '-e', tempfile.name]
		else:
			cmd = [ADDR2LINE, '-e', tempfile.name]

		log.debug("Original addresses" +  "\n".join(addresses))

		log.debug("The old offset we found was:"+str(offset))
		log.debug("vs the pefile one which is :"+str(EXEBASE))

		addresses = update_base(module, addresses, tempfile)
		log.debug(f'pefile addresses {", ".join(addresses)}')
		addresstring = '\n'.join(addresses)

		"""
		if offset != 0:
			#addresstring = "\n".join([hex(int(addr, 16) + offset)  for addr in addresses]) # old does not work
			for addr in addresses:
				addrint = int(addr, 16)
				log.debug("remap %s, masked %s - %s",hex(addrint), hex(addrint & 0xffffffff), hex(offset))
			addresstring = "\n".join([hex((int(addr, 16) & 0xffffffff) - (offset & 0xffffffff) + 0x140000000)  for addr in addresses]) # old does not work
		"""

		log.debug("Sent addresses:" + addresstring)
		log.debug('\tCommand line: ' + ' '.join(cmd))
		
		addr2linefilename = "addr2line-%s.txt"%(time.strftime("%Y%m%d-%H%M%S"))
		log.info('Keeping record of addr2line at: %s'%(addr2linefilename))
		addr2linefile = open(addr2linefilename,'w')
		addr2linefile.write(addresstring)
		addr2linefile.close()

		addr2line = Popen(cmd, stdin = PIPE, stdout = PIPE, stderr = PIPE)
		try:
			if addr2line.poll() == None:
				log.info("Communicating addresstring to addr2line")
				stdout, stderr = addr2line.communicate(addresstring.encode('utf-8'), timeout = 10)
			else:
				log.error("Addr2line communication failed!, addr2line.poll() was not None")
				stdout, stderr = addr2line.communicate()
			if stderr:
				log.debug('%s stderr: %s' % (ADDR2LINE, stderr))
			if addr2line.returncode != 0:
				fatal('%s exited with status %s' % (ADDR2LINE, addr2line.returncode))
		except TimeoutExpired:
			log.debug("addr2line unresponsive, killing and trying line-by-;line")
			addr2line.kill()
			stdouts = []
			goodaddresses = []
			for address in addresses:
				cmd = [ADDR2LINE, '-e', tempfile.name, address]
				log.debug(f"Trying line by line: {cmd}")
				addr2line = Popen(cmd, stdin = PIPE, stdout = PIPE, stderr = PIPE)
				try: 
					stdout, stderr = addr2line.communicate(timeout = 5)
				except TimeoutExpired:
					log.debug(f"Address timeouted:{address}") 
					addr2line.kill()
				else:
					log.debug(f"Address resolved: {address} to {stdout}")
					stdouts.append(stdout)
					goodaddresses.append(address)
			addresses = goodaddresses
			stdout = b'\n'.join(stdouts)



		log.debug('stderr addr2line: %s' %(stdout))
		log.info('\t\t[OK]')

	def fixup(addr, file, line):
		for psu in PATH_STRIP_UNTIL:
			if psu in file:
				file = file[file.index(psu)+len(psu):]
				break
		try:
			int(line)
			return module, addr, file, int(line)
		except:
			return module, addr, file, 1

	return [fixup(addr, *line.split(':')) for addr, line in zip(addresses, stdout.decode('utf-8').splitlines())]




def translate_(module_frames, frame_count, modules, modulearchive, module_offsets):
	'''\
	Translate the stacktrace given in (module_frames, frame_count) by repeatedly
	invoking addr2line on the debugging data for the modules.
	'''
	log.info('Translating stacktrace...')

	module_names = modules.keys()
	translated_stacktrace = [None] * frame_count
	for module, frames in iter(module_frames.items()):
		module_name = best_matching_module(module, module_names)
		indices, addrs = zip(*frames)   # unzip
		if module_name:
			offset = 0
			print("MODULE NAME",module_name, module)
			if 'spring' in module_name and 'spring' in module_offsets:
				offset = int(module_offsets['spring'],16)

			translated_frames = translate_module_addresses(module, modules[module_name], addrs, modulearchive,offset)
			for index, translated_frame in zip(indices, translated_frames):
				translated_stacktrace[index] = translated_frame
		else:
			log.debug('unknown module: %s', module)
			for i in range(len(indices)):
				translated_stacktrace[indices[i]] = (module, addrs[i], '??', 0)   # unknown

	log.debug('translated_stacktrace = %s', translated_stacktrace)
	log.info('\t[OK]')
	return translated_stacktrace


def translate_stacktrace(infolog, dbgsymdir = None):
	r'''\
	Translate a complete stacktrace to (module, address, filename, lineno) tuples.

	The input string may be a complete infolog (i.e. infolog.txt). At the very
	least it must contain the 'Spring XXX has crashed.' or 'Hang detection
	triggered for Spring XXX.' line and at least one stack frame.

	The output is a list of (module, address, filename, lineno) tuples,
	or (module, address, '??', 0) for each frame that could not be translated.

	Example of a remote call to the service in Python:
	(Note that tuples have become lists)

		>>> from xmlrpclib import ServerProxy   #doctest:+SKIP
		... proxy = ServerProxy('http://springrts.com:8000/')
		... proxy.translate_stacktrace(file('infolog.txt').read())
		[['C:\\Program Files\\Spring\\spring.exe', '0x0080F6F8', 'rts/Rendering/Env/GrassDrawer.cpp', 229],
		 ['C:\\Program Files\\Spring\\spring.exe', '0x008125DF', 'rts/Rendering/Env/GrassDrawer.cpp', 136],
		 ['C:\\Program Files\\Spring\\spring.exe', '0x00837E8C', 'rts/Rendering/Env/AdvTreeDrawer.cpp', 54],
		 ['C:\\Program Files\\Spring\\spring.exe', '0x0084189E', 'rts/Rendering/Env/BaseTreeDrawer.cpp', 57],
		 ['C:\\Program Files\\Spring\\spring.exe', '0x00402AA8', 'rts/Game/Game.cpp', 527],
		 ...
		 ['C:\\WINDOWS\\system32\\kernel32.dll(RegisterWaitForInputIdle+0x49)', '0x7C7E7077', '??', 0]]

	Example of a local call:

		>>> translate_stacktrace(file('infolog.txt').read())   #doctest:+SKIP
		[('C:\\Program Files\\Spring\\spring.exe', '0x0080F6F8', 'rts/Rendering/Env/GrassDrawer.cpp', 229),
		 ('C:\\Program Files\\Spring\\spring.exe', '0x008125DF', 'rts/Rendering/Env/GrassDrawer.cpp', 136),
		 ('C:\\Program Files\\Spring\\spring.exe', '0x00837E8C', 'rts/Rendering/Env/AdvTreeDrawer.cpp', 54),
		 ('C:\\Program Files\\Spring\\spring.exe', '0x0084189E', 'rts/Rendering/Env/BaseTreeDrawer.cpp', 57),
		 ('C:\\Program Files\\Spring\\spring.exe', '0x00402AA8', 'rts/Game/Game.cpp', 527),
		 ...
		 ('C:\\WINDOWS\\system32\\kernel32.dll(RegisterWaitForInputIdle+0x49)', '0x7C7E7077', '??', 0)]
	'''
	print ("begin translate")
	log.info('----- Start of translation process -----')
	
	
	infologfilename = "infolog-%s.txt"%(time.strftime("%Y%m%d-%H%M%S"))
	log.info('Keeping record of infolog at: %s'%(infologfilename))
	infologfile = open(infologfilename, 'w')
	infologfile.write(infolog)
	infologfile.flush()
	# TODO: add module checksum dump to spring, add code here to parse those.

	# With checksums, the idea is:
	# 1) put module_names and module_checksums in a dict which maps name to checksum
	# 2) use best_matching_module to find best matching item from module_names
	# 3) get its checksum
	# 4) download debugging symbols from ##/#############################, which
	#    shall be a symlink to the correct 7z file containing debugging symbols.
	# 5) perform translation..

	# Without checksums, the idea is:
	# 1) look in config/branch/rev folder
	# 2) build a list of modules based on *_dbg.7z files available in this folder
	#    (there's no guarantee of course that AI's, unitsync, etc. are of the
	#    same version as Spring.., but we'll have to live with that.)
	# 3) download debugging symbols for a module directly from config/branch/rev/...
	# 4) perform translation
	translated_stacktrace = ""
	try:
		config, branch, rev = detect_version_details(infolog)
		module_frames, frame_count = collect_stackframes(infolog)
		module_offsets = get_module_offsets(infolog)
		debugarchive, modules = collect_modules(config, branch, '', '', dbgsymdir)
		detect_exebase(infolog)

		if (debugarchive == None):
			fatal("No debug-archive(s) found for infolog.txt\n"+ '\n'.join( str(c) for c in [config, branch, rev,' \n '.join(str(mf) for mf in module_frames), frame_count,dbgsymdir]) )
		if frame_count == 0:
			fatal("No stack-trace found in infolog.txt")

		translated_stacktrace = translate_(module_frames, frame_count, modules, debugarchive, module_offsets)

	except FatalError:
		# FatalError is intended to reach the client => re-raise
		raise

	except Exception:
		# Log the real exception
		log.critical(traceback.format_exc())
		# Throw a new exception without leaking too much information
		raise FatalError('unhandled exception')
	
	infologfile.write(str(translated_stacktrace))
	infologfile.close()
	log.info('----- End of translation process -----')
	return translated_stacktrace


def run_xmlrpc_server():
	'''Run an XMLRPC server that publishes the translate_stacktrace function.'''
	from xmlrpc.server import DocXMLRPCServer as XMLRPCServer

	logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')

	with open(PIDFILE, 'w') as pidfile:
		pidfile.write('%s' % os.getpid())

	try:
		# Create server
		server = XMLRPCServer(LISTEN_ADDR)
		server.register_function(translate_stacktrace)

		# Run the server's main loop
		try:
			server.serve_forever()
		except KeyboardInterrupt:
			pass

	finally:
		os.remove(PIDFILE)


testmodules = """
[t=00:18:27.165915][f=-000001] Error: DLL information:
[t=00:18:27.165993][f=-000001] Error: 0x000000001dd60000	spring
[t=00:18:27.166013][f=-000001] Error: 0x00000000cfef0000	ntdll
[t=00:18:27.166039][f=-000001] Error: 0x00000000cf9c0000	KERNEL32
[t=00:18:27.166057][f=-000001] Error: 0x00000000cd850000	KERNELBASE
[t=00:18:27.166082][f=-000001] Error: 0x00000000cdf30000	ADVAPI32
[t=00:18:27.166097][f=-000001] Error: 0x00000000cfce0000	msvcrt
[t=00:18:27.166112][f=-000001] Error: 0x00000000ce0a0000	sechost
[t=00:18:27.166137][f=-000001] Error: 0x00000000cfd80000	RPCRT4
[t=00:18:27.166155][f=-000001] Error: 0x00000000cf0d0000	imagehlp
[t=00:18:27.166171][f=-000001] Error: 0x00000000cde30000	ucrtbase
[t=00:18:27.166188][f=-000001] Error: 0x00000000ce510000	SHELL32
[t=00:18:27.166213][f=-000001] Error: 0x00000000c6590000	GLU32
[t=00:18:27.166229][f=-000001] Error: 0x00000000cdc80000	msvcp_win
"""
def main(argc, argv):
	if (argc > 1):
		logging.basicConfig(format='%(message)s')
		log.setLevel(logging.DEBUG)
		
		get_module_offsets(testmodules)
		if (argv[1] == '--test'):
			import doctest
			doctest.testmod(optionflags = doctest.NORMALIZE_WHITESPACE + doctest.ELLIPSIS)
		else:
			try:
				infolog = open(argv[1], 'r')
				infologcontents = infolog.read()
				infologcontents = infologcontents.replace('\r\n', '\n')
				dbgsymdir = ((argc >= 3) and argv[2]) or None

				## config, branch, githash = detect_version_details(infolog.read())
				stacktrace = translate_stacktrace(infologcontents, dbgsymdir)
				for address in stacktrace:
					print(address)

			except FatalError:
				## redundant
				## print("FatalError:\n%s" % traceback.format_exc())
				return
			except IOError:
				print("IOError: file \"%s\" not readable" % argv[1])
				return

	else:
		run_xmlrpc_server()


if (__name__ == '__main__'):
	main(len(sys.argv), sys.argv)
