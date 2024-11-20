#!/bin/bash

cpabe-setup

cpabe-keygenEpsilon pub_key epsilon

cpabe-keygenDO pub_key master_key dummy 

cpabe-hideDU_ATTR pub_key DO_key A B C -o A1

cpabe-hideDU_ATTR pub_key DO_key D E -o A2

cpabe-keygenAA pub_key A1 -o AA1_key

cpabe-keygenAA pub_key A2 -o AA2_key

cpabe-keygenRRD pub_key du_blind AA1_key AA2_key 

cpabe-keygenDU pub_key DO_key rrd_key

cpabe-encryptCT_DO -k pub_key arthur.txt dummy "A and B and C and D or E"

cpabe-encryptCT_RRD pub_key arthur.txt.ct_do

cpabe-decryptCT_RRD -k pub_key DU_Out_key arthur.txt.ct_do.cpabe decryption_results

cpabe-decryptCT_DU pub_key user_key arthur.txt.ct_do arthur.txt.aes decryption_results -o arthur_FINAL.txt