import csv

te = []
re = []
se = set()
ans1, ans2 = [], []
with open('temp.csv') as csvfile:
    csv_reader = csv.reader(csvfile)
    te_header = next(csv_reader)
    for row in csv_reader:
        te.append(row)
for i in range(len(te)):
    te[i][0] = int(te[i][0])
    te[i][2] = int(te[i][2])
for pk in range(1,31):
    te = sorted(te, key = (lambda x:x[0]))
    re.clear()
    se.clear()
    print("sorted ok, <=5 started")
    for i in range(len(te) - 1):
        if i in se:
            continue
        for j in range(i+1, len(te)):
            if te[i][0] != te[j][0]:
                break
            if te[i][0] == te[j][0] and te[i][1] == te[j][1]:
                if abs(te[i][2] - te[j][2]) <= 5:
                    se.add(j)
                    re.append(te[j])
    print("<=5 ok, 100 started")
    count = 1
    for k in range(len(te) - 1):
        if k in se:
            continue
        if k > 0 and te[k][0] == te[k-1][0] and te[k][1] == te[k-1][1]:
            continue
        count = 1
        for t in range(k+1, len(te)):
            if te[k][0] != te[t][0]:
                break
            if te[k][0] == te[t][0] and te[k][1] == te[t][1]:
                count += 1
            if count >= pk*10:
                se.add(t)
                re.append(te[t])
    ans1.append(len(re))
    ans2.append(len(re)/len(te))
print("it is over")
