#!/usr/bin/env python

from __future__ import print_function
import matplotlib.pyplot as plt
import numpy as np
import sys


def runRocAnalysis(events):

	# np.where() returns row indices with positive P's (1)
	# np.take() returns values of the first argument array using indices from the second argument array
	p_idx = np.where(events[:,1] == 1)[0]
	p_val = np.take(events[:,0], p_idx)
	n_idx = np.where(events[:,1] == 0)[0]
	n_val = np.take(events[:,0], n_idx) 

	# plot event graph
	plt.figure(0)
	pos = plt.scatter(p_idx,p_val,s=50,c='blue')	# positive
	neg = plt.scatter(n_idx,n_val,s=50,c='green')	# negative
	plt.axis([0, (len(n_idx)+1), 0, 1.1])
	plt.legend([pos, neg],['Anomalous', 'Normal'], bbox_to_anchor=(1.04, 1), loc='upper left', ncol=1)
	plt.suptitle('Event Graph w/ Truth')
	plt.xlabel('Event')
	plt.ylabel('Score')
	plt.savefig('event_graph.jpg')
	plt.show(block=False)

	data = np.array([])
	step_size = 5
	for val in range(5,100,step_size):
		threshold = val/100.0
		true_positive = 0.0
		false_positive = 0.0
		false_negative = 0.0
		true_negative = 0.0
		for event in events:
			if (event[1] == 1 and event[0] >= threshold):
				true_positive += 1
			elif (event[1] == 0 and event[0] >= threshold):
				false_positive += 1
			elif (event[1] == 1 and event[0] < threshold):
				false_negative += 1
			elif (event[1] == 0 and event[0] < threshold):
				true_negative += 1 

		false_pos_rate = false_positive / (false_positive + true_negative)
		true_pos_rate = true_positive / (true_positive + false_negative)
		precision = true_positive / (true_positive + false_positive)
		recall = true_pos_rate
		accuracy = (true_positive + true_negative) / (false_positive + true_negative + true_positive + false_negative)
		if data.any(): 
			data = np.vstack([data, [threshold, false_pos_rate, true_pos_rate, precision, recall, accuracy]])
		else: 
			data = np.append(data, [threshold, false_pos_rate, true_pos_rate, precision, recall, accuracy])

	# confusion data matrix
	print(data)

	# optimal ROC threshold
	x = data[:,1]	# false positive rate
	y = data[:,2]	# true positive rate
	z = y - x
	opt_roc = data[np.argmax(z),0]
	print("Optimal ROC Threshold: "+str(opt_roc))

	# plot ROC
	plt.figure(1)
	roc = plt.scatter(x,y,c=z,s=50,cmap='RdYlGn')
	plt.axis([0, 1.1, 0, 1.1])
	plt.suptitle('ROC Graph')
	plt.xlabel('FP rate')
	plt.ylabel('TP rate')
	plt.savefig('roc_graph.jpg')
	plt.show(block=False)

	# optimal precision-recall threshold
	x = data[:,4]	# recall
	y = data[:,3]	# precision
	z = x * y
	opt_pre_re = data[np.argmax(z),0]
	print("Optimal Precision-Recall Threshold: "+str(opt_pre_re))

	# plot precision-recall
	plt.figure(2)
	roc = plt.scatter(x,y,c=z,s=50,cmap='RdYlGn')
	plt.axis([0, 1.1, 0, 1.1])	
	plt.suptitle('Precision-Recall Graph')
	plt.xlabel('Recall')
	plt.ylabel('Precision')
	plt.savefig('pr_graph.jpg')
	plt.show(block=False)

	# optimal accuracy threshold
	x = data[:,0]	# threshold
	y = data[:,5]	# accuracy
	z = y
	opt_acc = data[np.argmax(z),0]
	print("Optimal Accuracy Threshold: "+str(opt_acc))

	# plot accuracy
	plt.figure(3)
	roc = plt.scatter(x,y,c=z,s=50,cmap='RdYlGn')
	plt.axis([0, 1.1, 0, 1.1])	
	plt.suptitle('Accuracy Graph')
	plt.xlabel('Threshold')
	plt.ylabel('Accuracy')
	plt.savefig('pr_graph.jpg')
	plt.show(block=True)

	if (opt_roc == opt_pre_re == opt_acc):
		print("Threshold "+str(opt_roc)+" is optimal, all metrics agreed")
	elif (abs(opt_roc-opt_pre) <= step_size) and (abs(opt_roc-opt_acc) <= step_size):
		print("Threshold "+str(opt_roc)+" is likely optimal, all metrics within 1 step_size")
	else:
		print("Threshold optimum unsure, all metrics differ")
	
	return(data)


if __name__ == "__main__":
	# get event data from IDS
	events = np.array([[0.95,1],[0.14,0],[0.66,1],[0.78,1],[0.10,0],[0.91,0],[0.08,0],[0.76,1],[0.76,0],[0.85,1],[0.17,0],[0.24,0],
	[0.64,0],[0.20,0],[0.52,1],[0.09,0],[0.97,1],[0.90,1],[0.28,0],[0.71,1],[0.29,0],[0.14,0],[0.26,0],[0.86,0],[0.29,1],[0.13,0],[0.78,1],[0.18,0],[0.48,1],[0.58,1],[0.87,1]])

	# call analysis function
	runRocAnalysis(events)

