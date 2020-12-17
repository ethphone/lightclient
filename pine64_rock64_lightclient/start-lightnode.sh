#!/bin/bash
GRBD=.
MY_IP=$(hostname -I)
DD=`date '+%Y%m%d%H%M%S'`

ARGS="--nodiscover --networkid 5869 --syncmode full --rpc --rpcapi admin,db,eth,debug,miner,net,shh,txpool,personal,web3,clique"

echo "start"
nohup $GRBD/grbd --datadir fdata/n1 $ARGS --rpcaddr $MY_IP --rpccorsdomain "*" --rpcport 7764 --port 33460 --ethstats RBDLU-000:secret@112.171.26.14:8586 &

echo "All nodes configured. See 'data/logs' for logs, and run e.g. 'grbd attach fdata/n1/grbd.ipc' to attach to the first Grbd node."
