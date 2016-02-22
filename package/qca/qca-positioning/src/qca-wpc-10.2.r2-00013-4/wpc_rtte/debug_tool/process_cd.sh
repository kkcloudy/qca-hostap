#!/bin/sh
#/*
# * Copyright (c) 2011 Qualcomm Atheros, Inc..
# * All Rights Reserved.
# * Qualcomm Atheros Confidential and Proprietary.
# */ 
#Purpose: To take the cd.txt file generated from nbpserver run. 
#and convert the files into MATLAB readable format and c readable format. 
#Also this runs the binary file generated as debug tool, and generates CIR
#file. These files can be used to check the channel dump quality and the 
#FFT algorithm 

myFile=$1
cd="cd_fft_ap.txt"
pdac="process_data_ap_code.txt"
pdcc="process_data_c_code.txt"
count=1
cirap="cirap"
circ="cirCprog"
rm $pdac
rm $pdcc
while read LINE 
do 
`echo "$LINE" | cut -f11 -s >$cd`
./gen_file_ML_CP $cd 1
`echo "Data for channel dump $count" >>$pdac`
`echo "Data for channel dump $count" >>$pdcc`
./wpcRtteTest 2 >>$pdac
./wpc_rtte 2 >>$pdcc
cir_ap="cir.txt"
cir_ap="cir_cprogram.txt"
mv cir.txt $cirap$count.txt
mv cir_cprogram.txt $circ$count.txt
count=`expr $count + 1`

done < $myFile
