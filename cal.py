import matplotlib.pyplot as plt

def main(filename):
    x = []
    y1 = []
    y2 = []
    y3 = []
    with open(filename, 'r') as file:
        for line in file:
            data = line.split()
            x.append(int(data[0]))  # 第二个数字作为 x 坐标
            y1.append(int(data[1]))  # 第三个数字作为 y 坐标
            y2.append(int(data[2]))
            y3.append(int(data[3]))
    # 绘制点状图
    plt.scatter(x, y1)
    plt.scatter(x, y2)
    plt.scatter(x, y3)
    plt.xlabel('x')
    plt.ylabel('Y')
    #plt.title('点状图')
    plt.grid(False)
    plt.show()

if __name__ == "__main__":
    filename = "res.txt"  # 更改为您的文件名
    main(filename)
