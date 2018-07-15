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

verbose = False	# print more output
debug = True	# print more output

# parse truth data for a list of attacks
def parseTruthData(truth_text):
	copy = False
	count = 0
	attack = {'attack_name':'', 'datetime':'', 'duration':'','min_search_time':'','max_search_time':'','attacker_ip':'', 'victim_ip':'', 'ports':[], 'num_pkts':0, 'argus_lines':0}
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
				#date = date + timedelta(hours=5)	# adjust for GMT/DSL time offsets
				attack['datetime'] = date
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
				attack = {'attack_name':'', 'datetime':'', 'duration':'','min_search_time':'','max_search_time':'','attacker_ip':'', 'victim_ip':'', 'ports':[], 'num_pkts':0, 'argus_lines':0}
				copy = False

		if (line == "Date: 03/31/1999"):
			pieces = line.split(':')
			pieces = pieces[1].split('/')
			month = pieces[0].strip()
			day = pieces[1]
			year = pieces[2]
			copy = True

	return attacks



# parse Sguil log messages for alerts, looks for lines with the following format:
# 		2018-07-07 18:55:53 pid(3371)  Alert Received: 0 1 trojan-activity pching-VM-eth1-1 {1999-03-31 15:13:25} 2 15950 {ET MALWARE User-Agent (Win95)} 172.16.116.201 204.71.200.74 6 14461 80 1 2008015 9 293 293
def parseSguilAlerts(detection_text, attacks):
	true_pos_alerts = list()
	false_pos_alerts = list()
	false_neg_attacks = list()
	valid_attacks = list()
	for line in detection_text:
		if "Alert Received:" in line and "1999-03-31" in line:
			alert = {'datetime':'', 'src_addr':'', 'dst_addr':'', 'src_port':'', 'dst_port':'', 'reason':'', 'num_pkts':0, 'argus_lines':0}
			pieces = line.split('{')
			alert['datetime'] = pytz.utc.localize(datetime.strptime(pieces[1].split('}')[0], "%Y-%m-%d %H:%M:%S")-timedelta(hours=5))	# un-adjust for GMT/DSL time offsets
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
			for attack in attacks:
				if (attack['min_search_time'] < alert['datetime'] and alert['datetime'] < attack['max_search_time']):	# match time range
					if (alert['src_port'] in attack['ports'] or alert['dst_port'] in attack['ports']):							# match ports	
						if (alert['dst_addr'] == attack['attacker_ip'] or alert['dst_addr'] == attack['victim_ip']):				# match IP address
							if (alert['src_addr'] == attack['attacker_ip'] or alert['src_addr'] == attack['victim_ip']):
								if verbose: print("Alert Match: "+str(alert))
								true_pos_alerts.append(alert)
								valid_attacks.append(attack)
								break
							else:
								if verbose: print("Partial Hit: alert source IP "+alert['src_addr']+" does not match")
								false_pos_alerts.append(alert)

						elif (alert['src_addr'] == attack['attacker_ip'] or alert['src_addr'] == attack['victim_ip']):
							if verbose: print("Partial Hit: alert destination IP "+alert['dst_addr']+" does not match")
							false_pos_alerts.append(alert)
					
						else: # this is an alert that falls in time range but doesn't have an IP matches = false positive
							if verbose: print("False Positive: alert falls within attack time range but IP does not match")
							false_pos_alerts.append(alert)
					else:
						if verbose: print("False Positive: alert falls within attack time range but port does not match")
						false_pos_alerts.append(alert)

	# get the list of false negatives attacks (one's that weren't alerted on)
	for attack in attacks:
		for valid_attack in valid_attacks:
			if not cmp(attack, valid_attack):	# if a truth attack matches one of the 'valid' detected ones (true positive), then remove it...
				attacks.remove(attack)
				break
	# ... what's left over in 'attacks' list are the false negatives
	return true_pos_alerts, false_pos_alerts, attacks, valid_attacks



# to create parsable data from pcap file:
#	argus -r inside.tcpdump -w argus.raw
#	cat argus.raw | ra -n -c ';'  > argus.txt
def parseArgusData(argus_text, true_pos_alerts, false_pos_alerts, false_neg_attacks):
	print("Parsing argus data...")
	t0 = time.time()

	# there's no date in the raw data, so you have to hard code an initial date and then keep track of time roll over....
	date = datetime.strptime("1999-03-31", "%Y-%m-%d").date()
	date_time = pytz.utc.localize(datetime.combine(date, datetime.strptime("0:0:0.0", "%H:%M:%S.%f").time()))
	tp = False
	fp = False
	fn = False
	true_neg_traffic = {'num_pkts':0, 'argus_lines':0, 'total_lines':0, 'total_pkts':0}

	# parse argus line for information, try to match against alerts
	for line in argus_text:
		pieces = line.split(';')
		try:
			# comparison with alerts is only valid to second resolution, some of the argus lines are not time ordered on microsecond level
			start_time = pytz.utc.localize(datetime.strptime(pieces[0], "%H:%M:%S.%f").time().replace(microsecond=0))
			# b/c we have to keep track of time and roll over dates, this should only evaluate true when timestamps stradle midnight!
			if (start_time < pytz.utc.localize(date_time.time())): 
				print("[WARNING] Day change: ")#+date_time.time()+" to "+start_time)
				date = date + timedelta(days=1)
			date_time = datetime.combine(date, start_time) 	# convert to a datetime object for comparison later
			protocol = pieces[2]		
			src_addr = pieces[3]
			src_port = pieces[4]
			dst_addr = pieces[6]
			dst_port = pieces[7]
			num_pkts = int(pieces[8])
			true_neg_traffic['total_lines'] = true_neg_traffic['total_lines'] + 1	# count lines in file
			true_neg_traffic['total_pkts'] = true_neg_traffic['total_pkts'] + num_pkts	# count packets in file
			
			# check if this argus line/packets belongs to any true positive alerts
			for idx, val in enumerate(true_pos_alerts):
				# Can't guarentee src/dst in order from sguil.log so have to check either/or
				if ((src_addr == true_pos_alerts[idx]['src_addr']) and (dst_addr == true_pos_alerts[idx]['dst_addr'])) or\
				   ((src_addr == true_pos_alerts[idx]['dst_addr']) and (dst_addr == true_pos_alerts[idx]['src_addr'])):

					if ((src_port == true_pos_alerts[idx]['src_port']) and (dst_port == true_pos_alerts[idx]['dst_port'])) or\
			    	   ((src_port == true_pos_alerts[idx]['dst_port']) and (dst_port == true_pos_alerts[idx]['src_port'])):
	
						# FIXME this evaluation is costly, much more than the above comparisons. If evaluated first takes 36s as opposed to 9s
						# Test absolute time difference < some tolerance, shouldn't be any real difference between pcap and alert
						if (abs(date_time - true_pos_alerts[idx]['datetime']) < timedelta(hours=0,minutes=0,seconds=60)):
							true_pos_alerts[idx]['num_pkts'] = true_pos_alerts[idx]['num_pkts'] + num_pkts
							true_pos_alerts[idx]['argus_lines'] = true_pos_alerts[idx]['argus_lines'] + 1
							print(true_pos_alerts[idx])
							tp = True
							break	# FIXME 1 argus line might match more than 1 Snort/Sguil alert...

			if tp:	# if the packet was a true positive, go on to next line/packets
				tp = False
			
			else:	# else check if this line/packets belongs to any false positive alerts.
				# FIXME this section adds 55s
				for idx, val in enumerate(false_pos_alerts):
					if ((src_addr == false_pos_alerts[idx]['src_addr']) and (dst_addr == false_pos_alerts[idx]['dst_addr'])) or\
				   	   ((src_addr == false_pos_alerts[idx]['dst_addr']) and (dst_addr == false_pos_alerts[idx]['src_addr'])):
						if ((src_port == false_pos_alerts[idx]['src_port']) and (dst_port == false_pos_alerts[idx]['dst_port'])) or\
						   ((src_port == false_pos_alerts[idx]['dst_port']) and (dst_port == false_pos_alerts[idx]['src_port'])):
							# FIXME this evaluation is costly, much more than the above comparisons.
							if (abs(date_time - false_pos_alerts[idx]['datetime']) < timedelta(hours=0,minutes=0,seconds=20)):
								false_pos_alerts[idx]['num_pkts'] = false_pos_alerts[idx]['num_pkts'] + num_pkts
								false_pos_alerts[idx]['argus_lines'] = false_pos_alerts[idx]['argus_lines'] + 1
								fp = True
								break
				
				if fp:	# if the packet was a false positive, go on to next line/packets
					fp = False
				
				else:	# else check if this line/packets belongs to any attacks that weren't detected (false negatives)
					for idx, val in enumerate(false_neg_attacks):
						if ((src_port in false_neg_attacks[idx]['ports']) or (dst_port in false_neg_attacks[idx]['ports'])):
							if ((src_addr == false_neg_attacks[idx]['attacker_ip']) and (dst_addr == false_neg_attacks[idx]['victim_ip'])) or \
							   ((src_addr == false_neg_attacks[idx]['victim_ip']) and (dst_addr == false_neg_attacks[idx]['attacker_ip'])):
								# FIXME this evaluation is costly, much more than the above comparisons.
								if (abs(date_time - false_neg_attacks[idx]['datetime']) < timedelta(hours=0,minutes=0,seconds=20)):
									false_neg_attacks[idx]['num_pkts'] = false_neg_attacks[idx]['num_pkts'] + num_pkts
									false_neg_attacks[idx]['argus_lines'] = false_neg_attacks[idx]['argus_lines'] + 1
									fn = True
									break

					if fn:	# if the packet was a true positive, go on to next line/packets
						fn = False

					else:	# only option left is that the argus line/packets are true negatives
						true_neg_traffic['num_pkts'] = true_neg_traffic['num_pkts'] + num_pkts
						true_neg_traffic['argus_lines'] = true_neg_traffic['argus_lines'] + 1
					#	true_neg_traffic.append(argus)
					
		except Exception as e: print("[WARNING] Couldn't parse line: "+str(e))

	if debug: print("[DEBUG] parseArgusData() run time: "+str(time.time()-t0)+" seconds")
	return true_pos_alerts, false_pos_alerts, false_neg_attacks, true_neg_traffic



if __name__ == "__main__":
	print("Running IDS validation routine...")

	# read command line args
	if len(sys.argv) == 4:
		with open(sys.argv[1]) as fh:
			truth_text = fh.readlines()
		with open(sys.argv[2]) as fh:
			detection_text = fh.readlines()
		with open(sys.argv[3]) as fh:
			argus_text = fh.readlines()
	else:
		print("\n[Error] Specify args for a truth data file, detected alerts file (sguil), and raw traffic file (argus): \n"+\
				"	./check_snort_performance.py master_identification.list sguil.log argus.txt\n")
		sys.exit(1)

	# parse truth data for a list of attacks
	attacks = parseTruthData(truth_text) 

	# parse Sguil log messages for alerts
	true_pos_alerts, false_pos_alerts, false_neg_attacks, valid_attacks = parseSguilAlerts(detection_text, attacks)	
	if debug: print("# of true positive alerts:   "+str(len(true_pos_alerts)))
	if debug: print("# of false positive alerts:  "+str(len(false_pos_alerts)))
	if debug: print("# of false negative attacks: "+str(len(false_neg_attacks)))
	
	# attribute packets and sessions (argus lines) with true pos, false pos, false neg, and true neg alerts/attacks
	true_pos_alerts, false_pos_alerts, false_neg_attacks, true_neg_traffic = parseArgusData(argus_text, true_pos_alerts, false_pos_alerts, false_neg_attacks)

	if debug: 
		tp_lines = sum(item['argus_lines'] for item in true_pos_alerts)
		fp_lines = sum(item['argus_lines'] for item in false_pos_alerts)
		fn_lines = sum(item['argus_lines'] for item in false_neg_attacks)
		tn_lines = true_neg_traffic['argus_lines']
		total_lines = tp_lines+fp_lines+fn_lines+tn_lines
		print("# of argus lines corresponding to")
		print("  true positive alerts:   "+str(tp_lines))
		print("  false positive alerts:  "+str(fp_lines))
	 	print("  false negative attacks: "+str(fn_lines))
	 	print("  true negative traffic:  "+str(tn_lines))
	 	print("  total acounted for:     "+str(total_lines))
		print("  total in file:          "+str(true_neg_traffic['total_lines'])+"\n")
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
		print("  total in file:          "+str(true_neg_traffic['total_pkts'])+"\n")

	#sys.exit(0)
	# print valid alerts
	print("\n		Truth Data		        Alert Data")
	for idx, val in enumerate(true_pos_alerts):
		print(\
"Name:          "+valid_attacks[idx]['attack_name']+"			"+true_pos_alerts[idx]['reason']+"\n"+\
"Date:          "+str(valid_attacks[idx]['datetime'].date())+"			"+str(true_pos_alerts[idx]['datetime'].date())+"\n"+\
"Time:          "+str(valid_attacks[idx]['datetime'].time())+"  +"+str(valid_attacks[idx]['duration'])+"		"+str(true_pos_alerts[idx]['datetime'].time())+"\n"+\
"Addr:          "+valid_attacks[idx]['attacker_ip']+"			"+true_pos_alerts[idx]['src_addr']+"\n"+\
"	"+valid_attacks[idx]['victim_ip']+"			"+true_pos_alerts[idx]['dst_addr']+"\n"+\
"Port:          "+str(valid_attacks[idx]['ports'])+"				"+true_pos_alerts[idx]['src_port']+", "+true_pos_alerts[idx]['dst_port']+"\n"\
"Num Packets:   ?				"+str(true_pos_alerts[idx]['num_pkts'])+"\n"\
"Argus Lines:   ?				"+str(true_pos_alerts[idx]['argus_lines'])+"\n")

