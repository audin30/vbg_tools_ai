#!/usr/bin/env python3

import csv
import platform
import subprocess
import datetime
import time

INPUT_FILE = 'systems_list.csv'
OUTPUT_FILE = 'results.csv'
PING_COUNT = 1  # number of ping attempts per host
TIMEOUT = 2     # seconds

def ping_host(host):
	"""Ping a host and return True if it's online."""
	param = '-n' if platform.system().lower() == 'windows' else '-c'
	timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
	command = ['ping', param, str(PING_COUNT), timeout_param, str(TIMEOUT), host]
	try:
		result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		return result.returncode == 0
	except Exception:
		return False
	
def check_systems():
	results = []
	timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	
	with open(INPUT_FILE, 'r', newline='') as infile:
		reader = csv.DictReader(infile)
		for row in reader:
			host = row['hostname']
			status = "Online" if ping_host(host) else "Offline"
			print(f"{host}: {status}")
			results.append({'hostname': host, 'status': status, 'timestamp': timestamp})
			time.sleep(0.2)  # small delay to avoid flooding network
			
	# Write results
	with open(OUTPUT_FILE, 'w', newline='') as outfile:
		fieldnames = ['hostname', 'status', 'timestamp']
		writer = csv.DictWriter(outfile, fieldnames=fieldnames)
		writer.writeheader()
		writer.writerows(results)
		
if __name__ == "__main__":
	check_systems()