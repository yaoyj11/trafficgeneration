#!/bin/bash

num=10000
x=1
count=0
s=16
while [ $(($x * $x)) -le $num ]
do
        x=$((x<<1))
        s=$(($s - 1))
done
mask=$((24-$s))
echo "num"$num
echo "mask"$mask

for ((ix=0; ix<$x;ix++))
do
  for ((iy=0; iy<$x;iy++))
  do
    src=$((${ix} << $s))
    src2=$((src/256))
    src3=$((src%256))
    dst=$((${iy} << $s))
    dst2=$((dst/256))
    dst3=$((dst%256))
 #   ovs-ofctl add-flow br0 cookie=${count},dl_type=0x0800,priority=100,nw_src=1.${src2}.${src3}.0/${mask},nw_dst=2.${dst2}.${dst3}.0/${mask},action=output:ens6
    count=$(($count+1))
    if [ $(($count%10)) == 0 ];
    then
      echo $count
    fi
  done
done
echo $x
echo $s
