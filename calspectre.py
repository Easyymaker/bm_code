import matplotlib.pyplot as plt

def main(filename):
    x = []
    y = []

    with open(filename, 'r') as file:
        for line in file:
            data = line.split(",")
            x.append(int(data[0]))  # 第二个数字作为 x 坐标
            y.append(int(data[1]))  # 第三个数字作为 y 坐标

    # 绘制点状图
    plt.scatter(x, y)
    plt.xlabel('X')
    plt.ylabel('Y')
    #plt.title('点状图')
    plt.grid(False)
    plt.show()

if __name__ == "__main__":
    filename = "res1.txt"  # 更改为您的文件名
    main(filename)
