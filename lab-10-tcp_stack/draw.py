import matplotlib.pyplot as plt

def plot_cwnd(file_path):
    times = []
    cwnd_sizes = []

    with open(file_path, 'r') as file:
        for line in file:
            time, cwnd = map(float, line.split())
            times.append(time)
            cwnd_sizes.append(int(cwnd))

    plt.plot(times, cwnd_sizes)
    plt.title('CWND Sizes Over Time')
    plt.xlabel('Time')
    plt.ylabel('CWND Size')
    plt.grid(True)
    plt.show()

file_path = './cwnd.txt'
plot_cwnd(file_path)
