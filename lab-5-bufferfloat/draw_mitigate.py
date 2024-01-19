import sys
import os
import matplotlib.pyplot as plt
import math
def get_rtt(algo):
    rtt_file = algo + "/rtt.txt"
    if not os.path.exists(rtt_file):
        print('rtt file %s does not exist' % (rtt_file))
        return None
    # read the file line by line 
    # for every line, the first number is the time
    # the second last word "time=" is followed by the rtt
    # the last word "ms" is not needed
    rtt_list = []
    with open(rtt_file, 'r') as f:
        for line in f:
            # t is line.split()[0], but need to drop the last character ","
            t = float(line.split()[0][:-1])
            rtt = float(line.split()[-2].split('=')[1])
            rtt_list.append((t, rtt))
    # make t start at 0
    t0 = rtt_list[0][0]
    rtt_list = [(t - t0, rtt) for t, rtt in rtt_list]
    return rtt_list

# draw the rtt curve
# take one argument: qlen
# read from file qlen-<qlen>/rtt.txt
def draw_rtt(algo, log_enable = False):
    rtt_list = get_rtt(algo)
    if rtt_list is None:
        return
    # draw the rtt curve
    if (log_enable):
        plt.semilogy([t for t, rtt in rtt_list], [math.log(rtt) for t, rtt in rtt_list])
    else:
        plt.plot([t for t, rtt in rtt_list], [rtt for t, rtt in rtt_list])
    # legend algo for this curve
    
draw_rtt('taildrop')
draw_rtt('red', True)
draw_rtt('codel', True)
plt.xlabel('time')
plt.ylabel('rtt')
plt.title('mitigate')
plt.savefig('mitigate')
plt.close()