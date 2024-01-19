import os
import sys
import matplotlib.pyplot as plt
# take one argument: qlen
# read from file qlen-<qlen>/qlen.txt

def get_qlen(qlen):
    qlen_file = 'qlen-%d/qlen.txt' % (qlen)
    if not os.path.exists(qlen_file):
        print('qlen file %s does not exist' % (qlen_file))
        return None
    # read the file line by line 
    # every line is a tuple (time, qlen), separated by ","
    qlen_list = []
    with open(qlen_file, 'r') as f:
        for line in f:
            t, q = line.split(',')
            qlen_list.append((float(t), int(q)))
    # make t start at 0
    t0 = qlen_list[0][0]
    qlen_list = [(t - t0, q) for t, q in qlen_list]
    return qlen_list

# draw the qlen curve
# take one argument: qlen
# read from file qlen-<qlen>/qlen.txt
def draw_qlen(qlen):
    qlen_list = get_qlen(qlen)
    if qlen_list is None:
        return
    # draw the qlen curve
    plt.plot([t for t, q in qlen_list], [q for t, q in qlen_list])
    plt.xlabel('time')
    plt.ylabel('qlen')
    plt.title('qlen-%d' % (qlen))
    plt.savefig('qlen-%d/qlen.png' % (qlen))
    plt.close()

draw_qlen(int(sys.argv[1]))

# read from file qlen-<qlen>/rtt.txt
def get_rtt(qlen):
    rtt_file = 'qlen-%d/rtt.txt' % (qlen)
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
def draw_rtt(qlen):
    rtt_list = get_rtt(qlen)
    if rtt_list is None:
        return
    # draw the rtt curve
    plt.plot([t for t, rtt in rtt_list], [rtt for t, rtt in rtt_list])
    plt.xlabel('time')
    plt.ylabel('rtt')
    plt.title('qlen-%d' % (qlen))
    plt.savefig('qlen-%d/rtt.png' % (qlen))
    plt.close()

draw_rtt(int(sys.argv[1]))