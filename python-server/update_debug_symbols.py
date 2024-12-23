import os, sys
import tarfile
import subprocess
import logging

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
 
def download_unpack_symbols(archiveurl):
	logger.debug(f"Pass the parameter to the output of the github actions windows debug build as a command line arg to this script")
	symboltgz = archiveurl.rpartition("/")[2]
	if '105.' in symboltgz:
		engine_version = '105.' + symboltgz.rpartition("_windows")[0].rpartition("105.")[2]
	else:
		engine_version = '104.' + symboltgz.rpartition("_windows")[0].partition("104.")[2]
	targetdir = "default/" + engine_version
	# https://github.com/beyond-all-reason/spring/releases/download/spring_bar_%7BBAR%7D104.0.1-1977-g12700e0/spring_bar_.BAR.104.0.1-1977-g12700e0_windows-64-minimal-symbols.tgz

	logger.info(f'Archive URL = {archiveurl}, symboltgz = {symboltgz}, engine_version= {engine_version}')
	if runcmd("wget -q " + " " + archiveurl) != 0:
		logger.warning(f'Failed to download archive from {archiveurl} , exiting')
		return 

	runcmd("mkdir default")
	runcmd("mkdir " + targetdir)

	for filename in os.listdir(os.getcwd()):
		if engine_version in filename and filename.endswith(".tgz"):
			extract(filename)
	runcmd("mv -f install/* .")

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
	
	url = f"https://github.com/beyond-all-reason/spring/releases/download/spring_bar_%7B{branch}%7D{engineversion}/spring_bar_.{branch}.{engineversion}_windows-64-minimal-symbols.tgz"
	download_unpack_symbols(url)

if __name__ == "__main__":
	if len(sys.argv) >= 1:  
		download_unpack_symbols(sys.argv[1])
