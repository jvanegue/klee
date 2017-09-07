#!/usr/bin/python

import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import matplotlib.cbook as cbook

data1h = np.genfromtxt('hklee.covnew.stats', delimiter=',', names=True);
data2h = np.genfromtxt('hklee.icnt.stats', delimiter=',', names=True);
data3h = np.genfromtxt('hklee.nursdepth.stats', delimiter=',', names=True);
data4h = np.genfromtxt('hklee.randpath.stats', delimiter=',', names=True);
data5h = np.genfromtxt('hklee.cpicnt.stats', delimiter=',', names=True);
data6h = np.genfromtxt('hklee.md2u.stats', delimiter=',', names=True);
data7h = np.genfromtxt('hklee.nursqc.stats', delimiter=',', names=True);

data1 = np.genfromtxt('klee.covnew.stats', delimiter=',', names=True);
data2 = np.genfromtxt('klee.icnt.stats', delimiter=',', names=True);
data3 = np.genfromtxt('klee.nursdepth.stats', delimiter=',', names=True);
data4 = np.genfromtxt('klee.randpath.stats', delimiter=',', names=True);
data5 = np.genfromtxt('klee.cpicnt.stats', delimiter=',', names=True);
data6 = np.genfromtxt('klee.md2u.stats', delimiter=',', names=True);
data7 = np.genfromtxt('klee.nursqc.stats', delimiter=',', names=True);

# VANILLA KLEE DATA
awalltime = [data1['WallTime'], data2['WallTime'], data3['WallTime'], data4['WallTime'], data5['WallTime'],
             data6['WallTime'], data7['WallTime']]
astates = [data1['NumStates'], data2['NumStates'], data3['NumStates'], data4['NumStates'], data5['NumStates'],
           data6['NumStates'], data7['NumStates']]
ainstrcov = [data1['CoveredInstructions'], data2['CoveredInstructions'], data3['CoveredInstructions'], data4['CoveredInstructions'], data5['CoveredInstructions'],
             data6['CoveredInstructions'], data7['CoveredInstructions']]
amalloc = [data1['MallocUsage'], data2['MallocUsage'], data3['MallocUsage'], data4['MallocUsage'], data5['MallocUsage'],
           data6['MallocUsage'], data7['MallocUsage']]
anumobj = [data1['NumObjects'], data2['NumObjects'], data3['NumObjects'], data4['NumObjects'], data5['NumObjects'],
           data6['NumObjects'], data7['NumObjects']]
anumqueries = [data1['NumQueries'], data2['NumQueries'], data3['NumQueries'], data4['NumQueries'], data5['NumQueries'],
               data6['NumQueries'], data7['NumQueries']]
ainstruncov = [data1['UncoveredInstructions'], data2['UncoveredInstructions'], data3['UncoveredInstructions'], data4['UncoveredInstructions'],
               data5['UncoveredInstructions'], data6['UncoveredInstructions'], data7['UncoveredInstructions']]

# HEAP KLEE DATA 
hawalltime = [data1h['WallTime'], data2h['WallTime'], data3h['WallTime'], data4h['WallTime'], data5h['WallTime'],
             data6h['WallTime'], data7h['WallTime']]
hastates = [data1h['NumStates'], data2h['NumStates'], data3h['NumStates'], data4h['NumStates'], data5h['NumStates'],
           data6h['NumStates'], data7h['NumStates']]
hainstrcov = [data1h['CoveredInstructions'], data2h['CoveredInstructions'], data3h['CoveredInstructions'], data4h['CoveredInstructions'], data5h['CoveredInstructions'],
             data6h['CoveredInstructions'], data7h['CoveredInstructions']]
hamalloc = [data1h['MallocUsage'], data2h['MallocUsage'], data3h['MallocUsage'], data4h['MallocUsage'], data5h['MallocUsage'],
           data6h['MallocUsage'], data7h['MallocUsage']]
hanumobj = [data1h['NumObjects'], data2h['NumObjects'], data3h['NumObjects'], data4h['NumObjects'], data5h['NumObjects'],
           data6h['NumObjects'], data7h['NumObjects']]
hanumqueries = [data1h['NumQueries'], data2h['NumQueries'], data3h['NumQueries'], data4h['NumQueries'], data5h['NumQueries'],
               data6h['NumQueries'], data7h['NumQueries']]
hainstruncov = [data1h['UncoveredInstructions'], data2h['UncoveredInstructions'], data3h['UncoveredInstructions'], data4h['UncoveredInstructions'],
               data5h['UncoveredInstructions'], data6h['UncoveredInstructions'], data7h['UncoveredInstructions']]

colors = ['red', 'blue', 'green', 'purple', 'orange', 'yellow', 'black']
labels = ['covnew', 'instrcnt', 'wdepth', 'randpath', 'cpicnt', 'md2u', 'qc']

for j in range(1,3):
    
    for i in range(0, 7):

        title = "Unknown title"
        if (j == 1):
            walltime = awalltime[i][:2200]
            states = astates[i][:2200]
            instrcov = ainstrcov[i][:2200]
            malloc = amalloc[i][:2200]
            numobj = anumobj[i][:2200]
            numqueries = anumqueries[i][:2200]
            instruncov = ainstruncov[i][:2200]
            curcolor = colors[i]
            fignum = 1
            title = "Vanilla KLEE"
        else:
            walltime = hawalltime[i][:6000]
            states = hastates[i][:6000]
            instrcov = hainstrcov[i][:6000]
            malloc = hamalloc[i][:6000]
            numobj = hanumobj[i][:6000]
            numqueries = hanumqueries[i][:6000]
            instruncov = hainstruncov[i][:6000]
            curcolor = colors[i]
            fignum = 2
            title = "Heap KLEE"
        
        ## Convert seconds into hours for plotting
        curlabel = labels[i]
        hours = []
        hours[:] = walltime[:]

        ### Plotting code
        plt.figure(fignum)

        manager = plt.get_current_fig_manager()
        manager.resize(*manager.window.maxsize())
        
        plt.suptitle(title)

        plt.subplot(231)
        plt.title("States visited")
        #plt.xlabel('Time passed (hours)')
        plt.plot(hours, states, color=curcolor, label='States / time')

        ### Now how uncovered instruction count
        plt.subplot(232)
        plt.title("Instrs covered")
        #plt.xlabel('Time passed (hours)')
        plt.plot(hours, instrcov, color=curcolor, label='Instr Cov / time')

        ### Now Malloc usage plotting
        plt.subplot(233)
        plt.title("Malloc calls")
        #plt.xlabel('Time passed (hours)')
        plt.plot(hours, malloc, color=curcolor, label='Malloc calls / time')

        ### Now number of objects plotting
        plt.subplot(234)
        plt.title("NUM objects")
        #plt.xlabel('Time passed (hours)')
        plt.plot(hours, numobj, color=curcolor, label='Object num / time')

        ### Now Malloc usage plotting
        plt.subplot(235)
        plt.title("NUM queries")
        #plt.xlabel('Time passed (hours)')
        plt.plot(hours, numqueries, color=curcolor, label='Queries num / time')

        ### Now number of objects plotting
        ax = plt.subplot(236)
        plt.title("Instr Uncov")
        #plt.xlabel('Time passed (hours)')
        plt.plot(hours, instruncov, color=curcolor, label='Instr Uncov / time')

        handles, curlabels = ax.get_legend_handles_labels()
        plt.legend(handles, labels, loc='best', bbox_to_anchor=(0.5, -0.05), fancybox=True, shadow=True, ncol=7)

plt.tight_layout()
plt.show()


