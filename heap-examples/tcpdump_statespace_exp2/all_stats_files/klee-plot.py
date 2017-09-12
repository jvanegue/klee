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
data8h = np.genfromtxt('hklee.dfs.stats', delimiter=',', names=True);
data9h = np.genfromtxt('hklee.bfs.stats', delimiter=',', names=True);
data10h = np.genfromtxt('hklee.randstate.stats', delimiter=',', names=True);

data1 = np.genfromtxt('klee.covnew.stats', delimiter=',', names=True);
data2 = np.genfromtxt('klee.icnt.stats', delimiter=',', names=True);
data3 = np.genfromtxt('klee.nursdepth.stats', delimiter=',', names=True);
data4 = np.genfromtxt('klee.randpath.stats', delimiter=',', names=True);
data5 = np.genfromtxt('klee.cpicnt.stats', delimiter=',', names=True);
data6 = np.genfromtxt('klee.md2u.stats', delimiter=',', names=True);
data7 = np.genfromtxt('klee.nursqc.stats', delimiter=',', names=True);
data8 = np.genfromtxt('klee.dfs.stats', delimiter=',', names=True);
data9 = np.genfromtxt('klee.bfs.stats', delimiter=',', names=True);
data10 = np.genfromtxt('klee.randstate.stats', delimiter=',', names=True);

# VANILLA KLEE DATA
awalltime = [data1['WallTime'], data2['WallTime'], data3['WallTime'], data4['WallTime'], data5['WallTime'],
             data6['WallTime'], data7['WallTime'], data8['WallTime'], data9['WallTime'], data10['WallTime']]

astates = [data1['NumStates'], data2['NumStates'], data3['NumStates'], data4['NumStates'], data5['NumStates'],
           data6['NumStates'], data7['NumStates'], data8['NumStates'], data9['NumStates'], data10['NumStates']]

ainstrcov = [data1['CoveredInstructions'], data2['CoveredInstructions'], data3['CoveredInstructions'], data4['CoveredInstructions'], data5['CoveredInstructions'],
             data6['CoveredInstructions'], data7['CoveredInstructions'], data8['CoveredInstructions'], data9['CoveredInstructions'], data10['CoveredInstructions']]

amalloc = [data1['MallocUsage'], data2['MallocUsage'], data3['MallocUsage'], data4['MallocUsage'], data5['MallocUsage'],
           data6['MallocUsage'], data7['MallocUsage'], data8['MallocUsage'], data9['MallocUsage'], data10['MallocUsage']]

anumobj = [data1['NumObjects'], data2['NumObjects'], data3['NumObjects'], data4['NumObjects'], data5['NumObjects'],
           data6['NumObjects'], data7['NumObjects'], data8['NumObjects'], data9['NumObjects'], data10['NumObjects']]

anumqueries = [data1['NumQueries'], data2['NumQueries'], data3['NumQueries'], data4['NumQueries'], data5['NumQueries'],
               data6['NumQueries'], data7['NumQueries'], data8['NumQueries'], data9['NumQueries'], data10['NumQueries']]

ainstruncov = [data1['UncoveredInstructions'], data2['UncoveredInstructions'], data3['UncoveredInstructions'], data4['UncoveredInstructions'], data5['UncoveredInstructions'],
               data6['UncoveredInstructions'], data7['UncoveredInstructions'], data8['UncoveredInstructions'], data9['UncoveredInstructions'], data10['UncoveredInstructions']]

# HEAP KLEE DATA 
hawalltime = [data1h['WallTime'], data2h['WallTime'], data3h['WallTime'], data4h['WallTime'], data5h['WallTime'],
             data6h['WallTime'], data7h['WallTime'], data8h['WallTime'], data9h['WallTime'], data10h['WallTime']]

hastates = [data1h['NumStates'], data2h['NumStates'], data3h['NumStates'], data4h['NumStates'], data5h['NumStates'],
           data6h['NumStates'], data7h['NumStates'], data8h['NumStates'], data9h['NumStates'], data10h['NumStates']]

hainstrcov = [data1h['CoveredInstructions'], data2h['CoveredInstructions'], data3h['CoveredInstructions'], data4h['CoveredInstructions'], data5h['CoveredInstructions'],
             data6h['CoveredInstructions'], data7h['CoveredInstructions'], data8h['CoveredInstructions'], data9h['CoveredInstructions'], data10h['CoveredInstructions']]

hamalloc = [data1h['MallocUsage'], data2h['MallocUsage'], data3h['MallocUsage'], data4h['MallocUsage'], data5h['MallocUsage'],
            data6h['MallocUsage'], data7h['MallocUsage'], data8h['MallocUsage'], data9h['MallocUsage'], data10h['MallocUsage']]

hanumobj = [data1h['NumObjects'], data2h['NumObjects'], data3h['NumObjects'], data4h['NumObjects'], data5h['NumObjects'],
           data6h['NumObjects'], data7h['NumObjects'], data8h['NumObjects'], data9h['NumObjects'], data10h['NumObjects']]

hanumqueries = [data1h['NumQueries'], data2h['NumQueries'], data3h['NumQueries'], data4h['NumQueries'], data5h['NumQueries'],
               data6h['NumQueries'], data7h['NumQueries'], data8h['NumQueries'], data9h['NumQueries'], data10h['NumQueries']]

hainstruncov = [data1h['UncoveredInstructions'], data2h['UncoveredInstructions'], data3h['UncoveredInstructions'], data4h['UncoveredInstructions'], data5h['UncoveredInstructions'],
                data6h['UncoveredInstructions'], data7h['UncoveredInstructions'], data8h['UncoveredInstructions'], data9h['UncoveredInstructions'], data10h['UncoveredInstructions']]

hanumforks = [data1h['NumForks'], data2h['NumForks'], data3h['NumForks'], data4h['NumForks'], data5h['NumForks'],
            data6h['NumForks'], data7h['NumForks'], data8h['NumForks'], data9h['NumForks'], data10h['NumForks']]

hatotallocs = [data1h['TotAllocs'], data2h['TotAllocs'], data3h['TotAllocs'], data4h['TotAllocs'], data5h['TotAllocs'],
              data6h['TotAllocs'], data7h['TotAllocs'], data8h['TotAllocs'], data9h['TotAllocs'], data10h['TotAllocs']]

hasymallocs = [data1h['SymAllocs'], data2h['SymAllocs'], data3h['SymAllocs'], data4h['SymAllocs'], data5h['SymAllocs'],
               data6h['SymAllocs'], data7h['SymAllocs'], data8h['SymAllocs'], data9h['SymAllocs'], data10h['SymAllocs']]

colors = ['red', 'blue', 'green', 'purple', 'orange', 'yellow', 'black', 'magenta', 'cyan', 'olive']
labels = ['covnew', 'instrcnt', 'wdepth', 'randpath', 'cpicnt', 'md2u', 'qc', 'dfs', 'bfs', 'randstate']

klist = ["klee", "hklee"]
for j in klist:
    
    for i in range(0, 10):

        
        title = "Unknown title"
        if (j == "klee"):
            sample = 2000
            walltime = awalltime[i][:sample]
            states = astates[i][:sample]
            instrcov = ainstrcov[i][:sample]
            malloc = amalloc[i][:sample]
            numobj = anumobj[i][:sample]
            numqueries = anumqueries[i][:sample]
            instruncov = ainstruncov[i][:sample]
            numforks = [0] * sample
            totallocs = [0] * sample
            symallocs = [0] * sample
            curcolor = colors[i]
            fignum = 1
            title = "Vanilla KLEE"
        else:
            hsample = 6000
            walltime = hawalltime[i][:hsample]
            states = hastates[i][:hsample]
            instrcov = hainstrcov[i][:hsample]
            malloc = hamalloc[i][:hsample]
            numobj = hanumobj[i][:hsample]
            numqueries = hanumqueries[i][:hsample]
            instruncov = hainstruncov[i][:hsample]
            numforks = hanumforks[i][:hsample]
            totallocs = hatotallocs[i][:hsample]
            symallocs = hasymallocs[i][:hsample]
            curcolor = colors[i]
            fignum = 2
            title = "Heap KLEE"
        
        ## Convert seconds into hours for plotting
        curlabel = labels[i]
        hours = []
        hours[:] = walltime[:] / 60

        ### Plotting code
        plt.figure(fignum)
        manager = plt.get_current_fig_manager()
        manager.resize(*manager.window.maxsize())        
        plt.suptitle(title, fontsize=10)

        plt.subplot(331)
        plt.title("States visited", fontsize=10)
        plt.plot(hours, states, color=curcolor, label='States / time')
        plt.xlabel('Minutes', fontsize=10)
        plt.ylabel("Count", fontsize=10)
                
        ### Now how uncovered instruction count
        plt.subplot(332)
        plt.title("Instrs covered", fontsize=10)
        plt.plot(hours, instrcov, color=curcolor, label='Instr Cov / time')
        plt.xlabel('Minutes', fontsize=10)
        plt.ylabel("Count", fontsize=10)
                
        ### Now number of objects plotting
        plt.subplot(333)
        plt.title("Instr NonCov", fontsize=10)
        plt.plot(hours, instruncov, color=curcolor, label='Instr NonCov / time')
        plt.xlabel('Minutes', fontsize=10)
        plt.ylabel("Count", fontsize=10)
                
        ### Now Malloc usage plotting
        plt.subplot(334)
        plt.title("Malloc calls", fontsize=10)
        plt.plot(hours, malloc, color=curcolor, label='Malloc calls / time')
        plt.xlabel('Minutes', fontsize=10)
        plt.ylabel("Count", fontsize=10)
                
        ### Now number of objects plotting
        plt.subplot(335)
        plt.title("Memory objects", fontsize=10)
        plt.plot(hours, numobj, color=curcolor, label='Object num / time')
        plt.xlabel('Minutes', fontsize=10)
        plt.ylabel("Count", fontsize=10)
                
        ### Now Malloc usage plotting
        plt.subplot(336)
        plt.title("SMT queries", fontsize=10)
        plt.plot(hours, numqueries, color=curcolor, label='Queries num / time')
        plt.xlabel('Minutes', fontsize=10)
        plt.ylabel("Count", fontsize=10)

        ### Three extra indicators for HKLEE
        plt.subplot(337)
        plt.title("NUM Forks", fontsize=10)
        plt.plot(hours, numforks, color=curcolor, label='Forks num')
        plt.xlabel('Minutes', fontsize=10)
        plt.ylabel("Count", fontsize=10)

        plt.subplot(338)
        plt.title("TOT allocs", fontsize=10)
        plt.plot(hours, totallocs, color=curcolor, label='Malloc calls')
        plt.xlabel('Minutes', fontsize=10)
        plt.ylabel("Count", fontsize=10)

        ax = plt.subplot(339)
        plt.title("SYM allocs", fontsize=10)
        plt.plot(hours, symallocs, color=curcolor, label='SYM Malloc calls')
        plt.xlabel('Minutes', fontsize=10)
        plt.ylabel("Count", fontsize=10)
        
        handles, curlabels = ax.get_legend_handles_labels()
        plt.legend(handles, labels, loc='best', bbox_to_anchor=(0.5, -0.05), fancybox=True, shadow=True, ncol=10)

        if (j == "klee"):
            plt.savefig('klee-plot.png', dpi=700, pad_inches=20, fontsize=10)
        else:
            plt.savefig('hklee-plot.png', dpi=700, pad_inches=20, fontsize=10)

#plt.tight_layout()        
plt.show()


