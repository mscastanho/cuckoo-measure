#! /usr/bin/env bash

DSRC="/home/osboxes/Documents/cuckoo-measure/mininet"
cd $DSRC
FILENAME=$(ls $THOME | grep .out | head -n1)
TESTID=${FILENAME:9:-4}

if [ -z $TESTID ]; then
    echo "No output file found"
    exit 1
fi

DDST="/home/osboxes/Documents/results-cuckoo/$TESTID"

if [ ! -d $DDST ]; then
    mkdir $DDST
fi

mv *.ck *.out $DDST 