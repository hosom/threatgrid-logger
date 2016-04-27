#!/usr/bin/python

'''
This script will connect to Threatgrid, collecting a list of samples 
that have been analyzed by your organization. 

For all samples analyzed by the organization, a subset of the analysis.json
will be retrieved and printed to stdout. When run with 
'''

import json
import datetime
import time
import sys

from pythreatgrid import threatgrid
from argparse import ArgumentParser
from ConfigParser import ConfigParser

_NO_STATE = '''
No state file located! Is this your first run?
Initialize the state manually to prevent log overflow!
Open the state location and insert a date in the 
"%Y-%m-%dT%H:%M:%S.%f" date format in UTC.
'''

def get_state(statefile):
	'''Retrieve state from the state file.

	In other words--retrieve the date that was last checked for.

	Args:
		statefile (str): The file location of the state file.
	Returns:
		datetime.datetime: The date from the state file.
	'''
	try:
		with open(statefile, 'rb') as f:
			return datetime.datetime.strptime(f.readline().strip(), 
			"%Y-%m-%dT%H:%M:%S.%f")
	except IOError:
		sys.exit(_NO_STATE)

def write_state(statefile):
	'''Write the state to the state file. 

	Args:
		statefile (str): The file location of the state file.
	Returns:
		None
	'''
	with open(statefile, 'wb') as f:
		f.write('%s\n' % (datetime.datetime.utcnow().isoformat()))

def log(api_key, statefile):
	'''Retrieve subsets of the analysis.json and print them to stdout.

	Args:
		api_key (str): The API Key to use to access Threatgrid.
		statefile (str): The file location of the state file.
	Returns:
		None
	'''
	datestamp = get_state(statefile)
	write_state(statefile)

	options = {
		'api_key' : api_key,
		'after' : datestamp.isoformat(),
		'org_only' : True
	}

	# Fetch a list of samples since the last state write for the org
	samples = []
	for sample_group in threatgrid.samples(options):
		for sample in sample_group[u'data'][u'items']:
			samples.append(sample.get(u'id'))

	# Get the full report for each new sample. Since the reports are pretty
	# massive, only print the id, metadata, warnings, and iocs to stdout
	# as json objects
	for sample_id in samples:
		data = '' 
		for block in threatgrid.get_analysis(options, sample_id):
			data = data + block

		sample_document = json.loads(data)
		document = {}
		document[u'id'] = sample_id
		document[u'metadata'] = sample_document.get(u'metadata')
		document[u'warnings'] = sample_document.get(u'warnings')
		document[u'iocs'] = sample_document.get(u'iocs')
		if document.get(u'metadata') is not None:
			print(json.dumps(document))

def main():

	p = ArgumentParser()
	p.add_argument('-c', '--config', 
				default='./logger.conf', 
				help='Location of the configuration file for logger.')
	args = p.parse_args()

	c = ConfigParser()
	c.read(args.config)

	api_key = c.get('logger', 'api_key')
	statefile = c.get('logger', 'statefile')
	sleep_interval = float(c.get('logger', 'sleep_interval'))

	while True:
		log(api_key, statefile)
		time.sleep(sleep_interval)

if __name__ == '__main__':
	main()