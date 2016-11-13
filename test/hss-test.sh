#!/bin/bash

HSS=../hss.py

$HSS genkey billofrights

$HSS sign billofrights.prv amendment*.txt

$HSS verify billofrights.pub amendment*.txt

for file in *.sig *.pub *.prv; do 
    $HSS read $file > $file.dump
done


 