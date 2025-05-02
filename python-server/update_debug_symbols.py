import os, sys
import tarfile
import subprocess
import logging
import zstandard as zstd
logging.basicConfig(
	format='%(levelname)s: %(funcName)s : %(lineno)d - %(message)s',
	level=logging.DEBUG
)
logger = logging.getLogger(__name__)

#TODO: this unpacks debug symbols in-memory, which eats like 4gb, very bad!

os.nice(10)

#Should return the retval of the process
def runcmd_old(cmd):
	logger.debug(f"running cmd: {cmd}")
	return os.system(cmd)

def runcmd(command):
	logger.debug(f"Running cmd: {command}")
	"""Run a shell command and log its output."""
	try:
		# Use subprocess.run to execute the command and capture output
		result = subprocess.run(
			command,
			shell=True,
			text=True,               # Ensure output is returned as a string
			capture_output=True      # Capture both stdout and stderr
		)
		
		# Log the stdout and stderr
		if result.stdout:
			logger.info(f"Command output:\n{result.stdout}")
		if result.stderr:
			logger.warning(f"Command error output:\n{result.stderr}")
		
		# Optionally, check the return code
		if result.returncode != 0:
			logger.error(f"Command '{command}' failed with return code {result.returncode}")
		return result.returncode
	except Exception as e:
		logger.exception(f"An error occurred while running command: {command}")


def extract(tar_url, extract_path='.'):
	logger.info(f'tar_url = {tar_url}')
	tar = tarfile.open(tar_url, 'r')
	for item in tar:
		logger.debug(f'item name {item.name}')
		if item.name == "./install/spring.dbg" or item.name.startswith( "./install/AI"):
			tar.extract(item, extract_path)
			logger.debug(f'Extracted { item.name} to {extract_path}')
		if item.name.find(".tgz") != -1 or item.name.find(".tar") != -1:
			extract(item.name, "./" + item.name[:item.name.rfind('/')])
   
def extract_zstd(zstd_url, extract_path='.'):
	logger.info(f'zstd_url = {zstd_url}')
	with open(zstd_url, 'rb') as compressed_file:
		dctx = zstd.ZstdDecompressor()
		with dctx.stream_reader(compressed_file) as reader:
			with tarfile.open(fileobj=reader, mode='r|') as tar:
				for item in tar:
					logger.debug(f'extract zstd from {zstd_url} item name {item.name}')
					if item.name == "./spring.dbg" or item.name.startswith("./AI"):
						tar.extract(item, extract_path)
						logger.debug(f'Extracted {item.name} to {extract_path}')
					if item.name.find(".tgz") != -1 or item.name.find(".tar") != -1:
						extract(item.name, "./" + item.name[:item.name.rfind('/')])
 
def download_unpack_symbols(archiveurl):
	logger.debug(f"Pass the parameter to the output of the github actions windows debug build as a command line arg to this script")
	symboltgz = archiveurl.rpartition("/")[2]
	if '105.' in symboltgz:
		engine_version = '105.' + symboltgz.rpartition("_windows")[0].rpartition("105.")[2]
	elif 'rel2501' in symboltgz:
		# needs new engine version semantics to match the folder name in the 7z debug symbol file:
		engine_version = symboltgz.rpartition("_windows")[0].rpartition("_.rel2501.")[2]
	else:
		# latest engine version, where the incoming archiveurl is like:
		# https://github.com/beyond-all-reason/spring/releases/download/2025.04.01/spring_bar_.rel2501.2025.04.01_windows-64-minimal-symbols.tgz, symboltgz = spring_bar_.rel2501.2025.04.01_windows-64-minimal-symbols.tgz, engine_version= 2025.04.01
		# but the actual target is 
		# https://github.com/beyond-all-reason/RecoilEngine/releases/download/2025.04.01/recoil_2025.04.01_amd64-windows-dbgsym.tar.zst
		logger.info(f"Using latest engine version {archiveurl}")
		engine_version = archiveurl.rpartition("_amd64")[0].rpartition("recoil_")[2]
		archiveurl = f'https://github.com/beyond-all-reason/RecoilEngine/releases/download/{engine_version}/recoil_{engine_version}_amd64-windows-dbgsym.tar.zst'
		symboltgz = f'recoil_{engine_version}_amd64-windows-dbgsym.tar.zst'
		logger.info(f"Using latest engine version {engine_version} and archiveurl {archiveurl} and symboltgz {symboltgz}")
	targetdir = "default/" + engine_version
	# https://github.com/beyond-all-reason/spring/releases/download/spring_bar_%7BBAR%7D104.0.1-1977-g12700e0/spring_bar_.BAR.104.0.1-1977-g12700e0_windows-64-minimal-symbols.tgz

	logger.info(f'Archive URL = {archiveurl}, symboltgz = {symboltgz}, engine_version= {engine_version}')
	if runcmd("wget -q " + " " + archiveurl) != 0:
		logger.warning(f'Failed to download archive from {archiveurl} , exiting')
		return 

	runcmd("mkdir default")
	runcmd("mkdir " + targetdir)

	for filename in os.listdir(os.getcwd()):
		if engine_version in filename:
			if filename.endswith(".tgz"):
				extract(filename)
			if filename.endswith(".zst"):
				extract_zstd(filename)
	runcmd("mv -f install/* .")
	runcmd("ls -la")
	runcmd ("rm spring_dbg.7z")
	runcmd ("7za a -ms=off -m0=lzma2 -mx=1 -y spring_dbg.7z spring.dbg ./AI") # dont compress it much for speed, 
	runcmd ("mv -f spring_dbg.7z ./"+targetdir+'/')

	runcmd ("rm -r ./AI") 
	runcmd ("rm spring.dbg")
	runcmd ("rm "+symboltgz)
	runcmd ("rm -r ./install")

	# Clean up all old debug symbols whenever a new one is downloaded!
	runcmd("rm -r ./default/*.dbg")


def get_for_engineversion(engineversion, branch = 'BAR105'): #expects 105.1.1-2127-g9568247
	#https://github.com/beyond-all-reason/spring/releases/download/spring_bar_%7BBAR105%7D105.1.1-2156-g5cfd088/spring_bar_.BAR105.105.1.1-2156-g5cfd088_windows-64-minimal-symbols.tgz
	
	#url = f"https://github.com/beyond-all-reason/spring/releases/download/spring_bar_%7B{branch}%7D{engineversion}/spring_bar_.{branch}.{engineversion}_windows-64-minimal-symbols.tgz"
	# well the above doesnt work for new release names: e.g. ./default/2025.01.3/
	      # https://github.com/beyond-all-reason/spring/releases/download/2025.01.3/spring_bar_.rel2501.2025.01.3_windows-64-minimal-symbols.tgz
	url = f"https://github.com/beyond-all-reason/spring/releases/download/{engineversion}/spring_bar_.rel2501.{engineversion}_windows-64-minimal-symbols.tgz"
	
	# if engineversion 2025.04.01 or higher:
	if engineversion >= "2025.04.01":
		url = f'https://github.com/beyond-all-reason/RecoilEngine/releases/download/{engineversion}/recoil_{engineversion}_amd64-windows-dbgsym.tar.zst' 
 
	logger.info(f"Getting debug symbols for engine version {engineversion} and branch {branch} from url {url}")
	download_unpack_symbols(url)

if __name__ == "__main__":
	if len(sys.argv) >= 1:  
		download_unpack_symbols(sys.argv[1])
