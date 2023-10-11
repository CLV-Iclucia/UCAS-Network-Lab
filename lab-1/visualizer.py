import matplotlib.pyplot as plt
# read data from result.txt
file = open("result.txt", "r")
lines = file.readlines()
file.close()

bandwidth = []
result = []
for i in range(0, len(lines), 5):
    size = lines[i].split()[0]
    bandwidth.append(lines[i].split()[1])
    bandwidth.append(lines[i+1].split()[1])
    bandwidth.append(lines[i+2].split()[1])
    bandwidth.append(lines[i+3].split()[1])
    bandwidth.append(lines[i+4].split()[1])
    # divide the bandwidth by the first bandwidth to get the scale
    bandwidth[0] = round(float(bandwidth[0]), 2)
    for j in range(1, len(bandwidth)):
        bandwidth[j] = round(float(bandwidth[j]), 2) / bandwidth[0]
    bandwidth[0] = 1
    result.append(lines[i].split()[3])
    result.append(lines[i+1].split()[3])
    result.append(lines[i+2].split()[3])
    result.append(lines[i+3].split()[3])
    result.append(lines[i+4].split()[3])
    # keep two digits after the decimal point 
    result[0] = round(float(result[0]), 2)
    for j in range(1, len(result)):
        result[j] = result[0] / round(float(result[j]), 2)
    result[0] = 1
    # label the bandwidth and result beside each data point
    # for result keep two digits after the decimal point
    for j in range(2, len(bandwidth)):
        plt.text(bandwidth[j], result[j], str(bandwidth[j]) + ', ' + str(round(result[j], 2)))
    plt.plot(bandwidth, result, label = size)
    result = []
    bandwidth = []
# finally draw a line y=x
plt.plot([1, 100], [1, 100], label = 'linear improvement')
plt.xlabel('Bandwidth')
plt.ylabel('Result')
plt.legend()
plt.show()