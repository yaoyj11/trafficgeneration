#!/bin/bash
count=0
echo ${date}
num=$1
s=1
d=1
count=0
sm=28
dm=28
flag=0
while [ $(($s * $d)) -lt $num ]
do
    if [ $flag -eq 1 ];
    then
        s=$(($s<<1))
        sm=$(($sm - 1))
        flag=0
    else
        d=$(($d<<1))
        dm=$(($dm - 1))
        flag=1
    fi
done
smask=$((32-$sm))
dmask=$((32-$dm))
echo "num"$num
echo "smask"$smask
echo "dmask"$dmask
base1=16
base2=32
echo $s
echo $d

for ((ix=0; ix<$s;ix++))
do
  for ((iy=0; iy<$d;iy++))
  do  
    src=$((${ix} << $sm))
    src4=$(($src%256))
    s3=$(($src >> 8))
    src3=$(($s3%256))
    s2=$(($s3 >> 8))
    src2=$(($s2%256))
    s1=$(($s2 >> 8))
    src1=$(($s1 + base1))
    dst=$((${iy} << $dm))
    dst4=$(($dst%256))
    d3=$(($dst >> 8))
    dst3=$(($d3%256))
    d2=$(($d3 >> 8))
    dst2=$(($d2%256))
    d1=$(($d2 >> 8))
    dst1=$(($d1 + base2))
    ovs-ofctl add-flow br0 cookie=${count},dl_type=0x0800,priority=100,nw_src=${src1}.${src2}.${src3}.${src4}/${smask},nw_dst=${dst1}.${dst2}.${dst3}.${dst4}/${dmask},action=output:ens6
#    echo "nw_src=${src1}.${src2}.${src3}.${src4}/${smask},nw_dst=${dst1}.${dst2}.${dst3}.${dst4}/${dmask}"

    count=$(($count+1))
    if [ $(($count%10000)) == 0 ];
    then
      echo ${date}$count
    fi
  done
done
ovs-ofctl add-flow br0 cookie=${count},dl_type=0x0800,priority=10,nw_src=16.0.0.0/4,nw_dst=32.0.0.0/4,action=output:ens6

echo $smask
echo $dmask

echo ${date}
echo ${count}

