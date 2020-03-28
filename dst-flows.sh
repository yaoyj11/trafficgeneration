#!/bin/bash
count=0
echo ${date}
num=$1
d=1
count=0
dm=28
while [ $d -lt $num ]
do
    d=$(($d<<1))
    dm=$(($dm - 1))
done
dmask=$((32-$dm))
echo "num"$num
echo "dmask"$dmask
base2=32
echo $d
echo $dm

for ((iy=0; iy<$d;iy++))
do
  dst=$((${iy} << $dm))
  echo $dst
  dst4=$(($dst%256))
  d3=$(($dst >> 8))
  echo $d3
  dst3=$(($d3%256))
  d2=$(($d3 >> 8))
  dst2=$(($d2%256))
  d1=$(($d2 >> 8))
  dst1=$(($d1 + base2))
  echo $d2
  echo $d1
  ovs-ofctl add-flow br0 cookie=${count},dl_type=0x0800,priority=100,nw_dst=${dst1}.${dst2}.${dst3}.${dst4}/${dmask},action=output:ens6
#  echo "nw_dst=${dst1}.${dst2}.${dst3}.${dst4}/${dmask}"
  count=$(($count+1))
  if [ $(($count%10000)) == 0 ];
  then
    echo ${date}$count
  fi
done
ovs-ofctl add-flow br0 cookie=${count},dl_type=0x0800,priority=10, nw_dst=32.0.0.0/4,action=output:ens6

echo $smask
echo $dmask

echo ${date}
echo ${count}

