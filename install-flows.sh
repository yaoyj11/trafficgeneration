#!/bin/bash
count=0
num=1000000
echo ${date}
for src2 in {1..40}
do
  for src3 in {1..40}
  do
    for dst2 in {1..40}
    do
      for dst3 in {1..40}
      do
        ovs-ofctl add-flow br0 cookie=${count},dl_type=0x0800,priority=100,nw_src=1.${src2}.${src3}.0/24,nw_dst=2.${dst2}.${dst3}.0/24,action=output:ens6
        count=$(($count+1))
      done
    done
  done
done

ovs-ofctl add-flow br0 cookie=${count},dl_type=0x0800,priority=10,nw_src=1.0.0.0/8,nw_dst=2.0.0.0/8,action=output:ens6

echo ${date}
echo ${count}

