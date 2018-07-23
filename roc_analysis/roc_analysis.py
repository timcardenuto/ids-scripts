#!/usr/bin/env python

from __future__ import print_function
from builtins import input
import matplotlib.pyplot as plt
import plotly.graph_objs as go
import plotly
import numpy as np
import math
import sys

# turn on matplotlib grids
plt.rcParams['axes.grid'] = True
plt.rcParams['axes.axisbelow'] = True
# turn on matplotlib interactive mode
plt.ion()


# events is a numpy matrix where each row contains a score between 0 and 1, and the truth state value true(1) or false(0)
def runAnalysis(events, save=False, plot=False):

	data = np.array([])				# store the 'super' confusion matrix with all calculation combinations
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

		true_pos_rate = true_positive / (true_positive + false_negative)	# TPR, also called 'sensitivity', also called 'recall'
		false_pos_rate = false_positive / (false_positive + true_negative)	# FPR, also called 'fall-out'
		false_neg_rate = false_negative / (true_positive + false_negative)	# FNR, also called 'miss rate'
		true_neg_rate = true_negative / (false_positive + true_negative)	# TNR, also called 'specificity'

		if (true_positive + false_positive) == 0: # it's possible for this to happen if threshold is above all positives
			pos_predictive_val = float('inf')
			false_discovery_rate = float('inf')
		else:
			pos_predictive_val = true_positive / (true_positive + false_positive)	# Positive Predictive Value (PPV), also called precision
			false_discovery_rate = false_positive / (true_positive + false_positive) # False Discovery Rate (FDR)

		if (true_negative + false_negative) == 0: # it's possible for this to happen if threshold is below all negatives
			false_omission_rate = float('inf')
			neg_predictive_val = float('inf')
		else: 
			false_omission_rate = false_negative / (true_negative + false_negative)  # False Omission Rate (FOR)
			neg_predictive_val = true_negative / (true_negative + false_negative)    # Negative Predictive Value (NPV)

		accuracy = (true_positive + true_negative) / (false_positive + true_negative + true_positive + false_negative)
		f1_score = 2 * ((pos_predictive_val * true_pos_rate) / (pos_predictive_val + true_pos_rate))	# F1 score

		if (true_positive + false_positive) == 0 or (true_negative + false_negative) == 0:
			matthews_corr_coef = float('inf')
		else: 
			matthews_corr_coef = ((true_positive * true_negative) - (false_positive * false_negative)) / math.sqrt((true_positive + false_positive) * (true_positive + false_negative) * (true_negative + false_positive) * (true_negative + false_negative))	# Matthews Correlation Coefficient (MCC)
		bk_informedness = true_pos_rate + true_neg_rate - 1			# Bookmaker Informedness (BM)
		markedness = pos_predictive_val + neg_predictive_val - 1	# Markedness (MK)

		if false_pos_rate == 0:
			pos_likelihood_ratio = float('inf')
		else:
			pos_likelihood_ratio = true_pos_rate / false_pos_rate		# Positive Likelihood Ratio (PLR)

		if false_neg_rate == 0:
			neg_likelihood_ratio = float('inf')
		else:
			neg_likelihood_ratio = true_neg_rate / false_neg_rate		# Negative Likelihood Ratio (NLR)

		diagnostic_odds_ratio = pos_likelihood_ratio / neg_likelihood_ratio # Diagnostic Odds Ratio (DOR)

		if data.any(): 
			data = np.vstack([data, [threshold, true_positive, false_positive, false_negative, true_negative, true_pos_rate, false_pos_rate, false_neg_rate, true_neg_rate, pos_predictive_val, false_discovery_rate, false_omission_rate, neg_predictive_val, accuracy, f1_score, matthews_corr_coef, bk_informedness, markedness, pos_likelihood_ratio, neg_likelihood_ratio, diagnostic_odds_ratio]])
		else: 
			data = np.append(data, [threshold, true_positive, false_positive, false_negative, true_negative, true_pos_rate, false_pos_rate, false_neg_rate, true_neg_rate, pos_predictive_val, false_discovery_rate, false_omission_rate, neg_predictive_val, accuracy, f1_score, matthews_corr_coef, bk_informedness, markedness, pos_likelihood_ratio, neg_likelihood_ratio, diagnostic_odds_ratio])


	# store the cost function dimension results for each analysis
	z = np.zeros((len(data[:,1]),3))

	# optimal ROC threshold
	x = data[:,6]		# false positive rate
	y = data[:,5]		# true positive rate
	z[:,0] = (y - x)	# cost function as third dimension, optimize top left corner
	opt_roc = data[np.argmax(z[:,0]),0]
	print("Optimal ROC Threshold: "+str(opt_roc))

	# optimal precision-recall threshold
	x = data[:,5]		# recall
	y = data[:,9]		# precision
	z[:,1] = (x * y)	# optimize top right corner
	opt_pre_re = data[np.argmax(z[:,1]),0]
	print("Optimal Precision-Recall Threshold: "+str(opt_pre_re))

	# optimal accuracy threshold
	x = data[:,0]		# threshold
	y = data[:,13]		# accuracy
	z[:,2] = y			# optimize y axis evenly
	opt_acc = data[np.argmax(z[:,2]),0]
	print("Optimal Accuracy Threshold: "+str(opt_acc))

	if (opt_roc == opt_pre_re == opt_acc):
		print("Threshold "+str(opt_roc)+" is optimal, all metrics agreed")
	elif (abs(opt_roc-opt_pre_re) <= step_size) and (abs(opt_roc-opt_acc) <= step_size):
		print("Threshold "+str(opt_roc)+" is likely optimal, all metrics within 1 step_size")
	else:
		print("Threshold optimum unsure, all metrics differ")

	if save:
		f_handle = file('confusion_matrix.csv', 'w+')
		f_handle.write('Threshold,TP,FP,FN,TN,TPR,FPR,FNR,TNR,PPV,FDR,FOR,NPV,ACC,F1,MCC,BM,MK\n')
		np.savetxt(f_handle, data, delimiter=',')
		f_handle.close()
		f_handle = file('cost_function.csv', 'w+')
		f_handle.write('ROC,Precision-Recall,Accuracy\n')
		np.savetxt(f_handle, z, delimiter=',')
		f_handle.close()

	if plot:
		plotEventGraph(events, save)
		plotAnalysis(data, z, save)

	return data, z


def plotEventGraph(events, save=False):
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
	plt.legend([pos, neg],['Anomalous', 'Normal'], bbox_to_anchor=(0., .9, 1., .1), loc='upper center', ncol=2)
	plt.suptitle('Event Graph w/ Truth')
	plt.xlabel('Event')
	plt.ylabel('Score')
	plt.draw()

	if save:
		plt.savefig('images/event_graph.png')
		# create HTML event plot with plotly
		trace1 = go.Scatter(x=p_idx, y=p_val, name = 'Anomalous', mode='markers', marker=dict(size=16, color='green'))
		trace2 = go.Scatter(x=n_idx, y=n_val, name = 'Normal', mode='markers', marker=dict(size=16, color='blue'))
		layout = go.Layout(title='Event Graph w/ Truth', xaxis=dict(title='Event', titlefont=dict(size=18)), yaxis=dict(title='Score', titlefont=dict(size=18)))
		fig = go.Figure(data=[trace1, trace2], layout=layout)
		plotly.offline.plot(fig, filename='docs/event_graph.html')



# This plots all analysis
# data is a numpy matrix containing the 'super' confusion matrix data,
# each row contains: [Threshold, TP, FP, FN, TN, TPR, FPR, FNR, TNR, PPV, FDR, FOR, NPV, ACC, F1, MCC, BM, MK]
def plotAnalysis(data, cost, save=False):
	plotROC(data[:,6], data[:,5], cost[:,0], save)
	plotPR(data[:,5], data[:,9], cost[:,1], save)
	plotAccuracy(data[:,0], data[:,13], cost[:,2], save)


# plot ROC curve
def plotROC(x, y, z, save=False):
	plt.figure(1)
	roc = plt.scatter(x=x, y=y, c=z, s=50, cmap='RdYlGn')
	plt.axis([0, 1.1, 0, 1.1])
	plt.suptitle('Receiver Operating Characteristics (ROC)')
	plt.xlabel('False Positive Rate (FPR)')
	plt.ylabel('True Positive Rate (TPR)')
	plt.draw()

	if save:
		plt.savefig('images/roc_graph.png')
		# create HTML ROC plot with plotly
		trace = go.Scatter(x=x, y=y, mode='markers', marker=dict(size=16, color=z, colorscale=[[0, 'rgb(255, 0, 0)'], [0.5, 'rgb(255, 255, 0)'], [1.0, 'rgb(0, 128, 0)']], showscale=True))
		layout = go.Layout(title='Receiver Operating Characteristics (ROC)', xaxis=dict(title='False Positive Rate (FPR)', titlefont=dict(size=18)), yaxis=dict(title='True Positive Rate (TPR)', titlefont=dict(size=18)))
		fig = go.Figure(data=[trace], layout=layout)
		plotly.offline.plot(fig, filename='docs/roc_graph.html')


# plot precision-recall curve
def plotPR(x, y, z, save=False):
	plt.figure(2)
	roc = plt.scatter(x=x, y=y, c=z, s=50, cmap='RdYlGn')
	plt.axis([0, 1.1, 0, 1.1])	
	plt.suptitle('Precision-Recall')
	plt.xlabel('Recall')
	plt.ylabel('Precision')
	plt.draw()

	if save:
		plt.savefig('images/pr_graph.png')
		# create HTML PR plot with plotly
		trace = go.Scatter(x=x, y=y, mode='markers', marker=dict(size=16, color=z, colorscale=[[0, 'rgb(255, 0, 0)'], [0.5, 'rgb(255, 255, 0)'], [1.0, 'rgb(0, 128, 0)']], showscale=True))
		layout = go.Layout(title='Precision-Recall', xaxis=dict(title='Recall', titlefont=dict(size=18)), yaxis=dict(title='Precision', titlefont=dict(size=18)))
		fig = go.Figure(data=[trace], layout=layout)
		plotly.offline.plot(fig, filename='docs/pr_graph.html')


# plot accuracy curve
def plotAccuracy(x, y, z, save=False):
	plt.figure(3)
	roc = plt.scatter(x=x, y=y, c=z, s=50, cmap='RdYlGn')
	plt.axis([0, 1.1, 0, 1.1])
	plt.suptitle('Accuracy')
	plt.xlabel('Threshold')
	plt.ylabel('Accuracy')
	plt.draw()

	if save:
		plt.savefig('images/accuracy_graph.png')
		# create HTML Accuracy plot with plotly
		
		trace = go.Scatter(x=x, y=y, mode='markers', marker=dict(size=16, color=z, colorscale=[[0, 'rgb(255, 0, 0)'], [0.5, 'rgb(255, 255, 0)'], [1.0, 'rgb(0, 128, 0)']], showscale=True))
		layout = go.Layout(title='Accuracy', xaxis=dict(title='Threshold', titlefont=dict(size=18)), yaxis=dict(title='Accuracy', titlefont=dict(size=18)))
		fig = go.Figure(data=[trace], layout=layout)
		plotly.offline.plot(fig, filename='docs/accuracy_graph.html')


if __name__ == "__main__":
	print("Running ROC analysis routine...")

	# read command line args
	if len(sys.argv) == 1:
		# test data
		events = np.array([[0.95,1],[0.14,0],[0.66,1],[0.78,1],[0.10,0],[0.91,0],[0.08,0],[0.76,1],[0.76,0],[0.85,1],[0.17,0],[0.24,0],
		[0.64,0],[0.20,0],[0.52,1],[0.09,0],[0.97,1],[0.90,1],[0.28,0],[0.71,1],[0.29,0],[0.14,0],[0.26,0],[0.86,0],[0.29,1],[0.13,0],[0.78,1],[0.18,0],[0.48,1],[0.58,1],[0.87,1]])
		plot = True
		save = True

	elif len(sys.argv) == 4:
		events = np.genfromtxt(sys.argv[1], delimiter=',')

		if sys.argv[2] == 'true' or sys.argv[2] == 'True':
			plot = True
		elif sys.argv[2] == 'false' or sys.argv[2] == 'False':
			plot = False
		else:
			print("\n[Error] First optional argument for plotting must be either 'true' or 'false'\n")
			sys.exit(1)

		if sys.argv[3] == 'true' or sys.argv[3] == 'True':
			save = True
		elif sys.argv[3] == 'false' or sys.argv[3] == 'False':
			save = False
		else:
			print("\n[Error] Second optional argument for saving must be either 'true' or 'false'\n")
			sys.exit(1)

	else:
		print("\n[ERROR] Incorrect number of arguments. Must specify 3 arguments - an event data file, a plot boolean, and a save boolean. Also accepts no args for built in test.\n \
     roc_analysis.py events_data_file.csv true true \n")
		sys.exit(1)

	# call analysis function
	runAnalysis(events, plot, save)

	input("Press Enter to exit...")

