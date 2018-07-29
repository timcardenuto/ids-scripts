#!/usr/bin/env python
""" Validate Snort performance by cross-walking alerts with truth data """

from __future__ import print_function
import dateutil.parser
from datetime import datetime
from datetime import timedelta
import pytz
import re
import sys
import time
import json

verbose = False	# print more output
debug = True	# print more output


##################################################################################
# Parse truth data for a list of attacks
##################################################################################
def parseTruthData(truth_text):
	if debug: print("[DEBUG] Parsing truth data..."); t0 = time.time()
	copy = False
	count = 0
	#attack = {'attack_name':'', 'date_time':'', 'duration':'','min_search_time':'','max_search_time':'','attacker_ip':'', 'victim_ip':'', 'ports':[], 'num_pkts':0, 'connections':0, 'real_times':[], 'protocol':[], 'src_addr':[], 'src_port':[], 'dst_addr':[], 'dst_port':[]}
	attack = {'attack_name':'', 'date_time':'', 'duration':'','min_search_time':'','max_search_time':'','attacker_ip':'', 'victim_ip':'', 'ports':[],  'num_pkts':0, 'connections':0, 'detections':[]}
	attacks = list()
	for line in truth_text:
		line = line.strip() 
		if (copy == True):
			pieces = line.split(':')

			if (pieces[0] == "Name"):
				attack['attack_name'] = pieces[1].strip()

			elif (pieces[0] == "Start_Time"):
				hour = pieces[1].strip()
				minute = pieces[2]
				sec = pieces[3]

			elif (pieces[0] == "Duration"):
				dur_hour = pieces[1].strip()
				dur_min = pieces[2]
				dur_sec = pieces[3]
				date = dateutil.parser.parse(year+'-'+month+'-'+day+'T'+hour+':'+minute+':'+sec+'Z')
				attack['date_time'] = date
				attack['duration'] = timedelta(hours=int(dur_hour),minutes=int(dur_min),seconds=int(dur_sec))
				attack['min_search_time'] = date - timedelta(hours=int(dur_hour),minutes=int(dur_min),seconds=int(dur_sec))	
				attack['max_search_time'] = date + timedelta(hours=int(dur_hour),minutes=int(dur_min),seconds=int(dur_sec))
			
			elif (pieces[0] == "Attacker"):
				ip = pieces[1].strip()
				try: ip_fixed = '.'.join(str(int(part)) for part in ip.split('.')) 
				except: ip_fixed = ip			# needed for strings that aren't IP's like 'console'
				attack['attacker_ip'] = ip_fixed

			elif (pieces[0] == "Victim"):
				ip = pieces[1].strip()
				try: ip_fixed = '.'.join(str(int(part)) for part in ip.split('.')) 
				except: ip_fixed = ip			# needed for strings that aren't IP's like 'console'
				attack['victim_ip'] = ip_fixed

			elif (pieces[0] == "At_Victim"):
				temp = pieces[1]
				temp = re.split(r'{..?.?},?',temp)
				for port in temp:
					if port.strip().isdigit():
						attack['ports'].append(port.strip())
				attacks.append(attack)
				attack = {'attack_name':'', 'date_time':'', 'duration':'','min_search_time':'','max_search_time':'','attacker_ip':'', 'victim_ip':'', 'ports':[], 'num_pkts':0, 'connections':0, 'detections':[]}
				copy = False

		if (line == "Date: 03/31/1999"):
			pieces = line.split(':')
			pieces = pieces[1].split('/')
			month = pieces[0].strip()
			day = pieces[1]
			year = pieces[2]
			copy = True

	if debug: print("[DEBUG] parseTruthData() run time: "+str(time.time()-t0)+" seconds")
	return attacks


##################################################################################
# Parse Sguil log messages for alerts, looks for lines with the following format:
# 		2018-07-07 18:55:53 pid(3371)  Alert Received: 0 1 trojan-activity pching-VM-eth1-1 {1999-03-31 15:13:25} 2 15950 {ET MALWARE User-Agent (Win95)} 172.16.116.201 204.71.200.74 6 14461 80 1 2008015 9 293 293
##################################################################################
def parseSguilAlerts(detection_text, attacks):
	if debug: print("[DEBUG] Parsing sguil log..."); t0 = time.time()
	true_pos_alerts = list()
	false_pos_alerts = list()
	true_pos_attacks = list()
	for line in detection_text:
		if "Alert Received:" in line and "1999-03-31" in line:
			alert = {'date_time':'', 'src_addr':'', 'dst_addr':'', 'src_port':'', 'dst_port':'', 'reason':'', 'num_pkts':0, 'connections':0}
			pieces = line.split('{')
			# un-adjust for GMT/DSL time offsets here, something added +5 hours to the data
			alert['date_time'] = pytz.utc.localize(datetime.strptime(pieces[1].split('}')[0], "%Y-%m-%d %H:%M:%S")-timedelta(hours=5))	
			pieces = pieces[2].split('}')
			alert['reason'] = pieces[0].strip()
			pieces = pieces[1].strip().split(' ')
			alert['src_addr'] = pieces[0]
			alert['dst_addr'] = pieces[1]
			try:
				alert['src_port'] = pieces[3]
				alert['dst_port'] = pieces[4]	# there's no good way to parse, sometimes the 3rd number is the port and sometimes the 4th is
			except:
				if verbose: print("[Warning]  Alert ports can't be parsed: "+str(line))


			# try to match alert against truth data attacks
			tp = False
			for attack in attacks:
				# match IP address
				if ((alert['src_addr'] == attack['attacker_ip']) and (alert['dst_addr'] == attack['victim_ip'])) or \
				   ((alert['src_addr'] == attack['victim_ip']) and (alert['dst_addr'] == attack['attacker_ip'])):

					# match ports, sometimes truth doesn't specify ports! So we're less strict with this one
					if (alert['src_port'] in attack['ports']) or (alert['dst_port'] in attack['ports']) or (attack['ports'] == []):	

						# match time range
						# NOTE this uses the truth data duration, if something shows up in the data beyond that duration we don't count it...
						if (attack['min_search_time'] < alert['date_time'] and alert['date_time'] < attack['max_search_time']):
							if verbose: print("Alert match with attack "+attack['attack_name'])
							true_pos_alerts.append(alert)
							true_pos_attacks.append(attack)
							tp = True
							break

						else:
							if verbose: print("Partial match, alert didn't fall within time window: \nAlert: "+str(alert)+"\nAttack:"+str(attack))
					else:
						if verbose: print("Partial match, alert didn't share any ports: \nAlert: "+str(alert)+"\nAttack:"+str(attack))
				
			# this is an alert that falls in time range but doesn't have an IP matches = false positive
			if not tp:
				if verbose: print("False Positive: alert does not match any attack sufficiently "+str(alert))
				false_pos_alerts.append(alert)
					

	# get the list of false negatives attacks (one's that weren't alerted on)
	num_attacks = len(attacks)
	i = 0
	while i < len(attacks):
		for true_pos_attack in true_pos_attacks:
			if (attacks[i]['attack_name'] == true_pos_attack['attack_name']):	# if a truth attack matches one of the 'valid' detected ones (true positive), then remove it...
				attacks.remove(attacks[i])
				i = i - 1
				break
		i += 1
	# ... what's left over in 'attacks' list are the false negatives
	false_neg_attacks = attacks

	if debug: print("[DEBUG] parseSguilAlerts() run time: "+str(time.time()-t0)+" seconds")
	return true_pos_alerts, false_pos_alerts, false_neg_attacks, true_pos_attacks


##################################################################################
# Parse Suricata EVE alerts
##################################################################################
def parseEveAlerts(detection_text, attacks):
	if debug: print("[DEBUG] Parsing Suricata log..."); t0 = time.time()

	true_pos_alerts = list()
	false_pos_alerts = list()
	true_pos_attacks = list()
	for line in detection_text:
		blob = json.loads(line)
		if (blob['event_type'] == 'alert'):	# TODO check date to eliminate wasted time?
			alert = {'date_time':'', 'src_addr':'', 'dst_addr':'', 'src_port':'', 'dst_port':'', 'reason':'', 'num_pkts':0, 'connections':0}
			# un-adjust for GMT/DSL time offsets here, something added +5 hours to the data
			alert['date_time'] = pytz.utc.localize(dateutil.parser.parse(blob['timestamp']) - timedelta(hours=5))
			alert['src_addr'] = blob['src_ip']
			alert['dst_addr'] = blob['dest_ip']
			try:			
				alert['src_port'] = str(blob['src_port'])
				alert['dst_port'] = str(blob['dest_port'])
			except:
				if verbose: print("[WARNING] Ports not specified for alert: "+str(blob))
			alert['reason'] = blob['alert']['signature']


			# try to match alert against truth data attacks
			tp = False
			for attack in attacks:
				# match IP address
				if ((alert['src_addr'] == attack['attacker_ip']) and (alert['dst_addr'] == attack['victim_ip'])) or \
				   ((alert['src_addr'] == attack['victim_ip']) and (alert['dst_addr'] == attack['attacker_ip'])):

					# match ports, sometimes truth doesn't specify ports! So we're less strict with this one
					if (alert['src_port'] in attack['ports']) or (alert['dst_port'] in attack['ports']) or (attack['ports'] == []):	

						# match time range
						# NOTE this uses the truth data duration, if something shows up in the data beyond that duration we don't count it...
						if (attack['min_search_time'] < alert['date_time'] and alert['date_time'] < attack['max_search_time']):
							if verbose: print("Alert match with attack "+attack['attack_name'])
							true_pos_alerts.append(alert)
							true_pos_attacks.append(attack)
							tp = True
							break

						else:
							if verbose: print("Partial match, alert didn't fall within time window: \nAlert: "+str(alert)+"\nAttack:"+str(attack))
					else:
						if verbose: print("Partial match, alert didn't share any ports: \nAlert: "+str(alert)+"\nAttack:"+str(attack))
				
			# this is an alert that falls in time range but doesn't have an IP matches = false positive
			if not tp:
				if verbose: print("False Positive: alert does not match any attack sufficiently "+str(alert))
				false_pos_alerts.append(alert)
					

	# get the list of false negatives attacks (one's that weren't alerted on)
	num_attacks = len(attacks)
	i = 0
	while i < len(attacks):
		for true_pos_attack in true_pos_attacks:
			if (attacks[i]['attack_name'] == true_pos_attack['attack_name']):	# if a truth attack matches one of the 'valid' detected ones (true positive), then remove it...
				attacks.remove(attacks[i])
				i = i - 1
				break
		i += 1
	# ... what's left over in 'attacks' list are the false negatives
	false_neg_attacks = attacks		

	if debug: print("[DEBUG] parseSguilAlerts() run time: "+str(time.time()-t0)+" seconds")
	return true_pos_alerts, false_pos_alerts, false_neg_attacks, true_pos_attacks



##################################################################################
# Parse Argus pre-processed pcap data created from the following:
#	argus -r inside.tcpdump -w argus.raw
#	cat argus.raw | ra -n -c ';'  > argus.txt
##################################################################################
def parseArgusData(argus_text, true_pos_alerts, false_pos_alerts, false_neg_attacks):
	if debug: print("[DEBUG] Parsing argus data..."); t0 = time.time()

	# there's no date in the raw data, so you have to hard code an initial date and then keep track of time roll over....
	date = datetime.strptime("1999-03-31", "%Y-%m-%d").date()
	date_time = pytz.utc.localize(datetime.combine(date, datetime.strptime("0:0:0.0", "%H:%M:%S.%f").time()))
	tp = False
	fp = False
	fn = False
	true_neg_traffic = {'num_pkts':0, 'connections':0, 'total_file_pkts':0}

	# parse argus line for information, try to match against alerts
	count = 1.0
	total = len(argus_text)
	for line in argus_text:
		if debug: 	# print a percentage complete so you know it's still working...
			sys.stdout.write('\r')
			sys.stdout.write("[DEBUG] [%-20s] %d%%" % ('#'*int((count/total)*20), int((count/total)*100)))
			sys.stdout.flush()
			count += 1

		try:
			pieces = line.split(';')
			# comparison with alerts is only valid to second resolution, some of the argus lines are not time ordered on microsecond level
			start_time = pytz.utc.localize(datetime.strptime(pieces[0], "%H:%M:%S.%f").time().replace(microsecond=0))
			# b/c we have to keep track of time and roll over dates, this should only evaluate true when timestamps stradle midnight!
			if (start_time < pytz.utc.localize(date_time.time())): 
				print("\n[WARNING] Day change: ")#+date_time.time()+" to "+start_time)
				date = date + timedelta(days=1)
			date_time = datetime.combine(date, start_time) 	# convert to a datetime object for comparison later
			protocol = pieces[2]		
			src_addr = pieces[3]
			src_port = pieces[4]
			dst_addr = pieces[6]
			dst_port = pieces[7]
			num_pkts = int(pieces[8])
			true_neg_traffic['total_file_pkts'] = true_neg_traffic['total_file_pkts'] + num_pkts	# count packets in file
			

			# check if this argus line/packets belongs to any true positive alerts
			for idx, val in enumerate(true_pos_alerts):
				# Can't guarentee src/dst in order from sguil.log so have to check either/or
				if ((src_addr == val['src_addr']) and (dst_addr == val['dst_addr'])) or\
				   ((src_addr == val['dst_addr']) and (dst_addr == val['src_addr'])):

					if ((src_port == val['src_port']) and (dst_port == val['dst_port'])) or\
			    	   ((src_port == val['dst_port']) and (dst_port == val['src_port'])):
	
						# FIXME this evaluation is costly, much more than the above comparisons. If evaluated first takes 36s as opposed to 9s
						# Test absolute time difference < some tolerance, shouldn't be any real difference between pcap and alert
						if (abs(date_time - val['date_time']) < timedelta(hours=0,minutes=0,seconds=60)):
							true_pos_alerts[idx]['num_pkts'] = val['num_pkts'] + num_pkts
							true_pos_alerts[idx]['connections'] = val['connections'] + 1
							#print(true_pos_alerts[idx])
							tp = True
							break	# FIXME 1 argus line might match more than 1 Snort/Sguil alert...

			if tp:	# if the packet was a true positive, go on to next line/packets
				tp = False
			
			else:	# else check if this line/packets belongs to any false positive alerts.
				# FIXME this section adds 55s
				for idx, val in enumerate(false_pos_alerts):
					if ((src_addr == val['src_addr']) and (dst_addr == val['dst_addr'])) or\
				   	   ((src_addr == val['dst_addr']) and (dst_addr == val['src_addr'])):
						if ((src_port == val['src_port']) and (dst_port == val['dst_port'])) or\
						   ((src_port == val['dst_port']) and (dst_port == val['src_port'])):
							# FIXME this evaluation is costly, much more than the above comparisons.
							if (abs(date_time - val['date_time']) < timedelta(hours=0,minutes=0,seconds=20)):
								false_pos_alerts[idx]['num_pkts'] = val['num_pkts'] + num_pkts
								false_pos_alerts[idx]['connections'] = val['connections'] + 1
								fp = True
								break
				
				if fp:	# if the packet was a false positive, go on to next line/packets
					fp = False
				
				else:	# else check if this line/packets belongs to any attacks that weren't detected (false negatives)
					for idx, val in enumerate(false_neg_attacks):
						if ((src_port in val['ports']) or (dst_port in val['ports'])):
							if ((src_addr == val['attacker_ip']) and (dst_addr == val['victim_ip'])) or \
							   ((src_addr == val['victim_ip']) and (dst_addr == val['attacker_ip'])):
								# FIXME this evaluation is costly, much more than the above comparisons.
								if (abs(date_time - val['date_time']) < timedelta(hours=0,minutes=0,seconds=20)):
									false_neg_attacks[idx]['num_pkts'] = val['num_pkts'] + num_pkts
									false_neg_attacks[idx]['connections'] = val['connections'] + 1
									false_neg_attacks[idx]['detections'].append({'date_time':date_time, 'protocol':protocol, 'src_addr':src_addr, 'src_port':src_port, 'dst_addr':dst_addr, 'dst_port':dst_port,'num_pkts':num_pkts})
									'''
									false_neg_attacks[idx]['real_times'].append(date_time)
									false_neg_attacks[idx]['protocol'].append(protocol)
									false_neg_attacks[idx]['src_addr'].append(src_addr)
									false_neg_attacks[idx]['src_port'].append(src_port)
									false_neg_attacks[idx]['dst_addr'].append(dst_addr)
									false_neg_attacks[idx]['dst_port'].append(dst_port)
									'''
									fn = True
									break

					if fn:	# if the packet was a true positive, go on to next line/packets
						fn = False

					else:	# only option left is that the argus line/packets are true negatives
						true_neg_traffic['num_pkts'] = true_neg_traffic['num_pkts'] + num_pkts
						true_neg_traffic['connections'] = true_neg_traffic['connections'] + 1
					#	true_neg_traffic.append(argus)
					
		except Exception as e: print("\n[WARNING] Couldn't parse line: "+str(e))

	if debug: print("\n[DEBUG] parseArgusData() run time: "+str(time.time()-t0)+" seconds")
	return true_pos_alerts, false_pos_alerts, false_neg_attacks, true_neg_traffic



##################################################################################
# Script entry point
##################################################################################
if __name__ == "__main__":
	if debug: print("[DEBUG] Running IDS validation routine..."); t0 = time.time()

	# read command line args
	if len(sys.argv) == 5:
		with open(sys.argv[1]) as fh:
			truth_text = fh.readlines()
		with open(sys.argv[2]) as fh:
			detection_text = fh.readlines()
		with open(sys.argv[3]) as fh:
			argus_text = fh.readlines()
		log_format = sys.argv[4]
		if (log_format != "eve") and (log_format != "sguil"):
			print("\n[ERROR] 4th argument '"+log_format+"' is unsupported. Should be the IDS alerts file format, either 'eve' or 'sguil'.\n")
			sys.exit(1)
	else:
		print("\n[ERROR] Specify args for a truth data file, IDS alerts file, raw traffic file (argus), and alert log format (eve or sguil): \n"+\
				"	./check_ids_performance.py master_identification.list sguil.log argus.txt sguil\n")
		sys.exit(1)

	# parse truth data for a list of attacks
	attacks = parseTruthData(truth_text) 

	# parse log messages for alerts that match truth data
	if (log_format == 'eve'):   true_pos_alerts, false_pos_alerts, false_neg_attacks, true_pos_attacks = parseEveAlerts(detection_text, attacks)	
	if (log_format == 'sguil'): true_pos_alerts, false_pos_alerts, false_neg_attacks, true_pos_attacks = parseSguilAlerts(detection_text, attacks)	
	if debug:
		print("")
		print("# of true positive alerts:   "+str(len(true_pos_alerts)))
		print("# of false positive alerts:  "+str(len(false_pos_alerts)))
		print("# of false negative attacks: "+str(len(false_neg_attacks)))
		print("")
		
	# attribute packets and connections (argus lines) with true pos, false pos, false neg, and true neg alerts/attacks
	true_pos_alerts, false_pos_alerts, false_neg_attacks, true_neg_traffic = parseArgusData(argus_text, true_pos_alerts, false_pos_alerts, false_neg_attacks)

	if debug: 
		tp_lines = sum(item['connections'] for item in true_pos_alerts)
		fp_lines = sum(item['connections'] for item in false_pos_alerts)
		fn_lines = sum(item['connections'] for item in false_neg_attacks)
		tn_lines = true_neg_traffic['connections']
		total_lines = tp_lines+fp_lines+fn_lines+tn_lines
		print("")
		print("# of connections (argus lines) corresponding to")
		print("  true positive alerts:   "+str(tp_lines))
		print("  false positive alerts:  "+str(fp_lines))
	 	print("  false negative attacks: "+str(fn_lines))
	 	print("  true negative traffic:  "+str(tn_lines))
	 	print("  total acounted for:     "+str(total_lines))
		print("  total in file:          "+str(len(argus_text)-1)+"\n")
		tp_pkts = sum(item['num_pkts'] for item in true_pos_alerts)
		fp_pkts = sum(item['num_pkts'] for item in false_pos_alerts)
		fn_pkts = sum(item['num_pkts'] for item in false_neg_attacks)
		tn_pkts = true_neg_traffic['num_pkts']
		total_pkts = tp_pkts+fp_pkts+fn_pkts+tn_pkts
	 	print("# of packets corresponding to")
		print("  true positive alerts:   "+str(tp_pkts))
		print("  false positive alerts:  "+str(fp_pkts))
	 	print("  false negative attacks: "+str(fn_pkts))
	 	print("  true negative traffic:  "+str(tn_pkts))
	 	print("  total acounted for:     "+str(total_pkts))
		print("  total in file:          "+str(true_neg_traffic['total_file_pkts']))
		print("")


	if verbose: 
		# print true positive alerts, with truth data for reference
		print("###############################################################################")
		print("               Truth Data		     True Positive Alerts")
		last_attack_name = true_pos_attacks[0]['attack_name']
		total_attack_connections = 0
		total_attack_packet = 0
		for idx, val in enumerate(true_pos_alerts):
			# have to track this here because of how I tracked true positive alerts and attacks
			if (true_pos_attacks[idx]['attack_name'] != last_attack_name):
				print("## Total number of connections associated with attack "+last_attack_name+":   "+str(total_attack_connections))
				print("## Total number of packets associated with attack "+last_attack_name+":   "+str(total_attack_packet))
				print("")
				last_attack_name = true_pos_attacks[idx]['attack_name']
				total_attack_connections = 0
				total_attack_packet = 0
			total_attack_connections += val['connections']
			total_attack_packet += val['num_pkts']
			print(\
			"Name:          "+"{:<30}".format(true_pos_attacks[idx]['attack_name'])+val['reason']+"\n"+\
			"Date:          "+"{:<30}".format(str(true_pos_attacks[idx]['date_time'].date()))+str(val['date_time'].date())+"\n"+\
			"Time:          "+"{:<30}".format(str(true_pos_attacks[idx]['date_time'].time())+"  +"+str(true_pos_attacks[idx]['duration']))+str(val['date_time'].time())+"\n"+\
			"Addr:          "+"{:<30}".format(true_pos_attacks[idx]['attacker_ip'])+val['src_addr']+"\n"+\
			"               "+"{:<30}".format(true_pos_attacks[idx]['victim_ip'])+val['dst_addr']+"\n"+\
			"Port:          "+"{:<30}".format(str(true_pos_attacks[idx]['ports']))+val['src_port']+", "+val['dst_port']+"\n"\
			"Num Packets:   "+"{:<30}".format("?")+str(val['num_pkts'])+"\n"\
			"Connections:   "+"{:<30}".format("?")+str(val['connections'])+"\n")

		print("## Total number of connections associated with attack "+last_attack_name+":   "+str(total_attack_connections))
		print("## Total number of packets associated with attack "+last_attack_name+":   "+str(total_attack_packet))
		print("")

		# print false negative argus data, with truth data for reference
		# this prints *per connection* detected by argus, so you'll see repeated truth data attacks for every detected connection that matches
		print("###############################################################################")
		print("               Truth Data		     False Negative Argus Connections")
		for idx, val in enumerate(false_neg_attacks):
			for idx2, val2 in enumerate(val['detections']):
				print(\
				"Name:          "+"{:<30}".format(val['attack_name'])+val2['protocol']+"\n"+\
				"Date:          "+"{:<30}".format(str(val['date_time'].date()))+str(val2['date_time'].date())+"\n"+\
				"Time:          "+"{:<30}".format(str(val['date_time'].time())+"  +"+str(val['duration']))+str(val2['date_time'].time())+"\n"+\
				"Addr:          "+"{:<30}".format(val['attacker_ip'])+val2['src_addr']+"\n"+\
				"               "+"{:<30}".format(val['victim_ip'])+val2['dst_addr']+"\n"+\
				"Port:          "+"{:<30}".format(str(val['ports']))+val2['src_port']+", "+val2['dst_port']+"\n"\
				"Num Packets:   "+"{:<30}".format("?")+str(val2['num_pkts'])+"\n")

			print("## Total number of connections associated with attack "+val['attack_name']+":   "+str(val['connections']))
			print("## Total number of packets associated with attack "+val['attack_name']+":   "+str(val['num_pkts']))
			print("")

	if debug: print("[DEBUG] Total wall clock run time: "+str(time.time()-t0)+" seconds")

