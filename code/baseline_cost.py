"""Probe cost of the apply-and-diff baseline versus the cell check, for one fixed example per (d, n).
Baseline: install the planned policy and query every flow of F (Q1 and Q2 together).
Cell check: Q1 probes one flow per elementary cell inside M (Theorem 5); Q2 is predicted by the model."""
import random
N=256
def cells(boxes,d):
    segs=[]
    for j in range(d):
        K={0}
        for B in boxes:
            K.add(B[j][0])
            if B[j][1]+1<N: K.add(B[j][1]+1)
        segs.append(sorted(K))
    return segs
def inside(seg,lo,hi,N):  # count segments of a coordinate lying inside [lo,hi]
    K=seg+[N]
    return sum(1 for i in range(len(K)-1) if K[i]>=lo and K[i+1]-1<=hi)
def run(d,n,seed):
    rnd=random.Random(seed)
    def box():
        b=[]
        for _ in range(d):
            a=rnd.randrange(N); c=rnd.randrange(a,N); b.append((a,c))
        return b
    P=[box() for _ in range(n)]
    M=[(64,191)]*d
    boxes=P+[M]            # plan inserts a rule with box M
    segs=cells(boxes,d)
    total=1
    for s in segs: total*=len(s)
    inM=1
    for j,s in enumerate(segs): inM*=inside(s,M[j][0],M[j][1],N)
    return N**d, 128**d, total, inM
print("N=256 per dimension; M = [64,191] in every dimension; n random rules")
print("d  n   |F|=baseline(Q1+Q2)   |M|=baseline(Q1)   cells   cell probes for Q1")
for d in (1,2,3):
    for n in (2,5,10):
        F,Msz,t,q=run(d,n,1000*d+n)
        print(f"{d}  {n:2d}  {F:>14,d}  {Msz:>14,d}  {t:>8,d}  {q:>8,d}")
