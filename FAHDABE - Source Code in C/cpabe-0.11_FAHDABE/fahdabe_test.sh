#!/bin/bash
if [ 1 ]; then
	echo -e "Launching the FAHDABE testing phase... \n"
	sleep 2
    #

    # command execution
    cpabe-setup

    echo -e "\n"
    echo -e "\n"

     ########## cpabe-keygenEpsilon ##########

    # command execution
	cpabe-keygenEpsilon pub_key epsilon

    echo -e "\n"
    echo -e "\n"

     ########## cpabe-keygenDO ##########

    # command execution
    echo -e "----------------------------- Can Ignore----------------------------\n"

    echo -e "running cpabe-keygenDO to match with RRD key of 10 attributes......\n"
	cpabe-keygenDO pub_key master_key user_gid dummy_attribute -o DO_key_10

    echo -e "running cpabe-keygenDO to match with RRD key of 20 attributes......\n"
    cpabe-keygenDO pub_key master_key user_gid dummy_attribute -o DO_key_20

    echo -e "running cpabe-keygenDO to match with RRD key of 30 attributes......\n"
    cpabe-keygenDO pub_key master_key user_gid dummy_attribute -o DO_key_30

    echo -e "running cpabe-keygenDO to match with RRD key of 40 attributes......\n"
    cpabe-keygenDO pub_key master_key user_gid dummy_attribute -o DO_key_40

    echo -e "running cpabe-keygenDO to match with RRD key of 50 attributes......\n"
    cpabe-keygenDO pub_key master_key user_gid dummy_attribute -o DO_key_50

    echo -e "running cpabe-keygenDO to match with RRD key of 60 attributes......\n"
    cpabe-keygenDO pub_key master_key user_gid dummy_attribute -o DO_key_60

    echo -e "running cpabe-keygenDO to match with RRD key of 70 attributes......\n"
    cpabe-keygenDO pub_key master_key user_gid dummy_attribute -o DO_key_70

    echo -e "running cpabe-keygenDO to match with RRD key of 80 attributes......\n"
    cpabe-keygenDO pub_key master_key user_gid dummy_attribute -o DO_key_80

    echo -e "running cpabe-keygenDO to match with RRD key of 90 attributes......\n"
    cpabe-keygenDO pub_key master_key user_gid dummy_attribute -o DO_key_90

    echo -e "running cpabe-keygenDO to match with RRD key of 100 attributes......\n"
    cpabe-keygenDO pub_key master_key user_gid dummy_attribute -o DO_key_100

    echo -e "----------------------------- Can Ignore----------------------------\n"

    echo -e "\n"
    echo -e "\n"

    ########## cpabe-hideDU_ATTR ##########

    # command execution
	echo -e "running cpabe-hideDU_ATTR with 10 attributes......\n"
	cpabe-hideDU_ATTR pub_key DO_key_10 WJP brQ Wax cvj BTM Crc pKW tbM qzT mJS -o A10 

    echo -e "running cpabe-hideDU_ATTR with 20 attributes......\n"
	cpabe-hideDU_ATTR pub_key DO_key_20 byV FSA nnC FqX ESd zWs ntc MFc xKX SEg xcr UGH VJV xKJ SxJ NXv TQQ vah BYH Buf -o A20

    echo -e "running cpabe-hideDU_ATTR with 30 attributes......\n"
	cpabe-hideDU_ATTR pub_key DO_key_30 AVP GhC vNC zfs mge CpT Uqc HKC pkm qmE FbQ Nkn pve twR jCt RPU fZY cyj JaP PaQ VgE ZsA CYk euu QQv NJP JDH PTG Ssp XAh -o A30 

    echo -e "running cpabe-hideDU_ATTR with 40 attributes......\n"
	cpabe-hideDU_ATTR pub_key DO_key_40 yDG pZY Jxc kPs qUB dZV Xjn xHv csB uWe TTb SGU bVg mhJ ZBD VqZ Uem hhA YXn JUW quN jHR YDw fQC HmJ hSe zPQ NBu hEV HMk MyG zSC VbN eXK AQE MSx duJ huv ruF kxd -o A40 

    echo -e "running cpabe-hideDU_ATTR with 50 attributes......\n"
	cpabe-hideDU_ATTR pub_key DO_key_50 VEr Sef Vcc cPW knx mRY vmq Wsr myZ fRC PRX Wdv AVr MvJ ENw SkW qCQ eEc uJq hgK xVz WFC szb Ckm qWs wfW vuw qNt pvt nEM RTj xnH WsM MVg DwK mxe rJk JeD cgC ReQ xJz gTw fcv MHN nNs DFC dGw NeV XQp Mac -o A50 

    echo -e "running cpabe-hideDU_ATTR with 60 attributes......\n"
	cpabe-hideDU_ATTR pub_key DO_key_60 gjg NdR vVz Dpx AmC Enq ZVu Wwv Mty HCR fbx YWH WrW Zzs cwF Gjr rwk pss QDF muH qpa Sav JQf hrs vqA pCY KZX ShX JSs Kag CNc JvE nJg Gqb Bhd azN vZn eQT XwN MTY JYh ejX UAW Caj kum sfZ qtb Yag JDc EDZ cpk KWZ dgc SWk Ycz kpD Xku MRd tXw nvs -o A60 

    echo -e "running cpabe-hideDU_ATTR with 70 attributes......\n"
	cpabe-hideDU_ATTR pub_key DO_key_70 YcD wkE cjk UXp rWn EGW CKm dNh jHk saD CMe uwa dhq cKz Uxw YbE URQ PFZ mRv uAK rbU yvS Eyz kPX jvq TjS seY gNv Qxt bDF juE GUC wJB HTG fFA muV CHC Met Eaq JMV gyh Tyu uDD dSM bYk UpY YMk gZp nXR PRn AVM aQp vkv pbM Efq CMX Rnm hgT uQZ frj Ycv FkF jvw MUP Mbj nZf Xvj uzA Jwg GpW -o A70 

    echo -e "running cpabe-hideDU_ATTR with 80 attributes......\n"
	cpabe-hideDU_ATTR pub_key DO_key_80 cyc nSx aQm MBp rJW yGR YQD waR JzR pqj rNu PdD JEz Tvu BPA GNv sTk bkJ ERY FFK aQj Uzp wjp kab JSN gha Qbb udd YwB Svh EjZ uvM hSh Pcp cKr eFN hzm TCD SQr pkU EBS pEM Qcv Snj usf VyS DtV Wbs cJz uUk hYJ GmR hBK fnB kkt nXT byP pBm RvK azh Wxv rXU NFJ EJj MwV uJS peN Fkr VpP grP aXM YqY Yzk Xdt pFh yFV CAX ZBe bcs ZKr -o A80 

    echo -e "running cpabe-hideDU_ATTR with 90 attributes......\n"
	cpabe-hideDU_ATTR pub_key DO_key_90 trH gkC cqF VcG Eev HUu NPW bey xqw gHf fem DnM rHM nwA RZb rqY yHy hYQ mjk pTr Akw ENB rtJ MFY bjx BAr HmF zzC VSK UnN MHY HTZ EvH Pkv zKM Xtc dJN jQN wSG dZZ rsp mMp wNR mED GFn Gtt rhT tvF Fgy bQr nHB sxH Kbf Xvt SAG kGg tpR UtG xse zup uPT yDx uGz dMM QXk kxm mrB yDu xJC KTk SYK UPh dhS BNJ UdB MGt KKf Mre jNM dKk Czj xST nTW MrK wcp yQv DkK SRv qMt PaC -o A90

    echo -e "running cpabe-hideDU_ATTR with 100 attributes......\n"
	cpabe-hideDU_ATTR pub_key DO_key_100 WWg wuW zah yAF sTf fsS jEU qAw ZMZ rUe XFG hkt XSW MVg Xpy WkD Zwp kXW SYH scP PCb TrH GYQ MXT Mzy FeC CAH UhG DmB RaW TjY Ncm XUS rbT vcm MHd uGN dxE sVa XCn psG FuN bqW NNv ynf bym BTe rSA NSG Jzc DHc dPN gBz kBY StF muf wsM Ghy AEu Nnq VFg PVw mUq daD GEy ZvM YUr pvB VpZ pfQ ymP rKz nFj PnH ZNB FJZ ape Vqk amm hKW zcb Qvh dqY WBQ NNV sYr RfY dyp Vvc TCg CWa HzK RYb MvU xPT GRE WEb tqF BnR Suh -o A100 

    echo -e "\n"
    echo -e "\n"
    
    ########## cpabe-keygenAA ##########
    # command execution
	echo -e "running cpabe-keygenAA for AA10_key......\n"
	cpabe-keygenAA pub_key A10 user_gid -o AA10_key

    echo -e "running cpabe-keygenAA for AA20_key......\n"
	cpabe-keygenAA pub_key A20 user_gid -o AA20_key

    echo -e "running cpabe-keygenAA for AA30_key......\n"
	cpabe-keygenAA pub_key A30 user_gid -o AA30_key

    echo -e "running cpabe-keygenAA for AA40_key......\n"
	cpabe-keygenAA pub_key A40 user_gid -o AA40_key

    echo -e "running cpabe-keygenAA for AA50_key......\n"
	cpabe-keygenAA pub_key A50 user_gid -o AA50_key

    echo -e "running cpabe-keygenAA for AA60_key......\n"
	cpabe-keygenAA pub_key A60 user_gid -o AA60_key

    echo -e "running cpabe-keygenAA for AA70_key......\n"
	cpabe-keygenAA pub_key A70 user_gid -o AA70_key

    echo -e "running cpabe-keygenAA for AA80_key......\n"
	cpabe-keygenAA pub_key A80 user_gid -o AA80_key

    echo -e "running cpabe-keygenAA for AA90_key......\n"
	cpabe-keygenAA pub_key A90 user_gid -o AA90_key

    echo -e "running cpabe-keygenAA for AA100_key......\n"
	cpabe-keygenAA pub_key A100 user_gid -o AA100_key

    echo -e "\n"
    echo -e "\n"

    ########## cpabe-keygenRRD ##########
    # command execution
    echo -e "running cpabe-keygenRRD for AA10_key......\n"
	cpabe-keygenRRD pub_key du_blind AA10_key -o rrd10_key

    echo -e "running cpabe-keygenRRD for AA20_key......\n"
	cpabe-keygenRRD pub_key du_blind AA10_key AA20_key -o rrd20_key

    echo -e "running cpabe-keygenRRD for AA30_key......\n"
	cpabe-keygenRRD pub_key du_blind AA10_key AA20_key AA30_key -o rrd30_key

    echo -e "running cpabe-keygenRRD for AA40_key......\n"
	cpabe-keygenRRD pub_key du_blind AA10_key AA20_key AA30_key AA40_key -o rrd40_key

    echo -e "running cpabe-keygenRRD for AA50_key......\n"
	cpabe-keygenRRD pub_key du_blind AA10_key AA20_key AA30_key AA40_key AA50_key -o rrd50_key

    echo -e "running cpabe-keygenRRD for AA60_key......\n"
	cpabe-keygenRRD pub_key du_blind AA10_key AA20_key AA30_key AA40_key AA50_key AA60_key -o rrd60_key

    echo -e "running cpabe-keygenRRD for AA70_key......\n"
	cpabe-keygenRRD pub_key du_blind AA10_key AA20_key AA30_key AA40_key AA50_key AA60_key AA70_key -o rrd70_key

    echo -e "running cpabe-keygenRRD for AA80_key......\n"
	cpabe-keygenRRD pub_key du_blind AA10_key AA20_key AA30_key AA40_key AA50_key AA60_key AA70_key AA80_key -o rrd80_key

    echo -e "running cpabe-keygenRRD for AA90_key......\n"
	cpabe-keygenRRD pub_key du_blind AA10_key AA20_key AA30_key AA40_key AA50_key AA60_key AA70_key AA80_key AA90_key -o rrd90_key

    echo -e "running cpabe-keygenRRD for AA100_key......\n"
	cpabe-keygenRRD pub_key du_blind AA10_key AA20_key AA30_key AA40_key AA50_key AA60_key AA70_key AA80_key AA90_key AA100_key -o rrd100_key

    echo -e "\n"
    echo -e "\n"


    ########## cpabe-keygenDU ##########
    # command execution
    echo -e "\n\n running cpabe-keygenDU for rrd10_key......\n"
    cpabe-keygenDU pub_key DO_key_10 rrd10_key DU_Out_key_10 user_gid -o user_key10

    echo -e "\n\n running cpabe-keygenDU for rrd20_key......\n"
    cpabe-keygenDU pub_key DO_key_20 rrd20_key DU_Out_key_20 user_gid -o user_key20

    echo -e "\n\n running cpabe-keygenDU for rrd30_key......\n"
    cpabe-keygenDU pub_key DO_key_30 rrd30_key DU_Out_key_30 user_gid -o user_key30

    echo -e "\n\n running cpabe-keygenDU for rrd40_key......\n"
    cpabe-keygenDU pub_key DO_key_40 rrd40_key DU_Out_key_40 user_gid -o user_key40

    echo -e "\n\n running cpabe-keygenDU for rrd50_key......\n"
    cpabe-keygenDU pub_key DO_key_50 rrd50_key DU_Out_key_50 user_gid -o user_key50

    echo -e "\n\n running cpabe-keygenDU for rrd60_key......\n"
    cpabe-keygenDU pub_key DO_key_60 rrd60_key DU_Out_key_60 user_gid -o user_key60

    echo -e "\n\n running cpabe-keygenDU for rrd70_key......\n"
    cpabe-keygenDU pub_key DO_key_70 rrd70_key DU_Out_key_70 user_gid -o user_key70

    echo -e "\n\n running cpabe-keygenDU for rrd80_key......\n"
    cpabe-keygenDU pub_key DO_key_80 rrd80_key DU_Out_key_80 user_gid -o user_key80

    echo -e "\n\n running cpabe-keygenDU for rrd90_key......\n"
    cpabe-keygenDU pub_key DO_key_90 rrd90_key DU_Out_key_90 user_gid -o user_key90

    echo -e "\n\n running cpabe-keygenDU for rrd100_key......\n"
    cpabe-keygenDU pub_key DO_key_100 rrd100_key DU_Out_key_100 user_gid -o user_key100

    echo -e "\n"
    echo -e "\n"


    ########## cpabe-encryptCT_DO ##########
    # command execution
    touch arthur10.txt
    echo "Test for Fahdabe" >> arthur10.txt
    echo -e "\n\n running cpabe-encryptCT_DO for 10 Attr in policy......\n"
    cpabe-encryptCT_DO -o arthur10.txt.ct_do pub_key arthur10.txt epsilon dummy_attribute "WJP and brQ and Wax and cvj and BTM and Crc and pKW and tbM and qzT and mJS"
    
    touch arthur20.txt
    echo "Test for Fahdabe" >> arthur20.txt
    echo -e "\n\n running cpabe-encryptCT_DO for 20 Attr in policy......\n"
    cpabe-encryptCT_DO -o arthur20.txt.ct_do pub_key arthur20.txt epsilon dummy_attribute "byV and FSA and nnC and FqX and ESd and zWs and ntc and MFc and xKX and SEg and xcr and UGH and VJV and xKJ and SxJ and NXv and TQQ and vah and BYH and Buf"
    
    touch arthur30.txt
    echo "Test for Fahdabe" >> arthur30.txt
    echo -e "\n\n running cpabe-encryptCT_DO for 30 Attr in policy......\n"
    cpabe-encryptCT_DO -o arthur30.txt.ct_do pub_key arthur30.txt epsilon dummy_attribute "AVP and GhC and vNC and zfs and mge and CpT and Uqc and HKC and pkm and qmE and FbQ and Nkn and pve and twR and jCt and RPU and fZY and cyj and JaP and PaQ and VgE and ZsA and CYk and euu and QQv and NJP and JDH and PTG and Ssp and XAh"
    
    touch arthur40.txt
    echo "Test for Fahdabe" >> arthur40.txt
    echo -e "\n\n running cpabe-encryptCT_DO for 40 Attr in policy......\n"
    cpabe-encryptCT_DO -o arthur40.txt.ct_do pub_key arthur40.txt epsilon dummy_attribute "yDG and pZY and Jxc and kPs and qUB and dZV and Xjn and xHv and csB and uWe and TTb and SGU and bVg and mhJ and ZBD and VqZ and Uem and hhA and YXn and JUW and quN and jHR and YDw and fQC and HmJ and hSe and zPQ and NBu and hEV and HMk and MyG and zSC and VbN and eXK and AQE and MSx and duJ and huv and ruF and kxd"
   
    touch arthur50.txt
    echo "Test for Fahdabe" >> arthur50.txt
    echo -e "\n\n running cpabe-encryptCT_DO for 50 Attr in policy......\n"
    cpabe-encryptCT_DO -o arthur50.txt.ct_do pub_key arthur50.txt epsilon dummy_attribute "VEr and Sef and Vcc and cPW and knx and mRY and vmq and Wsr and myZ and fRC and PRX and Wdv and AVr and MvJ and ENw and SkW and qCQ and eEc and uJq and hgK and xVz and WFC and szb and Ckm and qWs and wfW and vuw and qNt and pvt and nEM and RTj and xnH and WsM and MVg and DwK and mxe and rJk and JeD and cgC and ReQ and xJz and gTw and fcv and MHN and nNs and DFC and dGw and NeV and XQp and Mac"
   
    touch arthur60.txt
    echo "Test for Fahdabe" >> arthur60.txt
    echo -e "\n\n running cpabe-encryptCT_DO for 60 Attr in policy......\n"
    cpabe-encryptCT_DO -o arthur60.txt.ct_do pub_key arthur60.txt epsilon dummy_attribute "gjg and NdR and vVz and Dpx and AmC and Enq and ZVu and Wwv and Mty and HCR and fbx and YWH and WrW and Zzs and cwF and Gjr and rwk and pss and QDF and muH and qpa and Sav and JQf and hrs and vqA and pCY and KZX and ShX and JSs and Kag and CNc and JvE and nJg and Gqb and Bhd and azN and vZn and eQT and XwN and MTY and JYh and ejX and UAW and Caj and kum and sfZ and qtb and Yag and JDc and EDZ and cpk and KWZ and dgc and SWk and Ycz and kpD and Xku and MRd and tXw and nvs"
    
    touch arthur70.txt
    echo "Test for Fahdabe" >> arthur70.txt
    echo -e "\n\n running cpabe-encryptCT_DO for 70 Attr in policy......\n"
    cpabe-encryptCT_DO -o arthur70.txt.ct_do pub_key arthur70.txt epsilon dummy_attribute "YcD and wkE and cjk and UXp and rWn and EGW and CKm and dNh and jHk and saD and CMe and uwa and dhq and cKz and Uxw and YbE and URQ and PFZ and mRv and uAK and rbU and yvS and Eyz and kPX and jvq and TjS and seY and gNv and Qxt and bDF and juE and GUC and wJB and HTG and fFA and muV and CHC and Met and Eaq and JMV and gyh and Tyu and uDD and dSM and bYk and UpY and YMk and gZp and nXR and PRn and AVM and aQp and vkv and pbM and Efq and CMX and Rnm and hgT and uQZ and frj and Ycv and FkF and jvw and MUP and Mbj and nZf and Xvj and uzA and Jwg and GpW"
    
    touch arthur80.txt
    echo "Test for Fahdabe" >> arthur80.txt
    echo -e "\n\n running cpabe-encryptCT_DO for 80 Attr in policy......\n"
    cpabe-encryptCT_DO -o arthur80.txt.ct_do pub_key arthur80.txt epsilon dummy_attribute "cyc and nSx and aQm and MBp and rJW and yGR and YQD and waR and JzR and pqj and rNu and PdD and JEz and Tvu and BPA and GNv and sTk and bkJ and ERY and FFK and aQj and Uzp and wjp and kab and JSN and gha and Qbb and udd and YwB and Svh and EjZ and uvM and hSh and Pcp and cKr and eFN and hzm and TCD and SQr and pkU and EBS and pEM and Qcv and Snj and usf and VyS and DtV and Wbs and cJz and uUk and hYJ and GmR and hBK and fnB and kkt and nXT and byP and pBm and RvK and azh and Wxv and rXU and NFJ and EJj and MwV and uJS and peN and Fkr and VpP and grP and aXM and YqY and Yzk and Xdt and pFh and yFV and CAX and ZBe and bcs and ZKr"

    touch arthur90.txt
    echo "Test for Fahdabe" >> arthur90.txt
    echo -e "\n\n running cpabe-encryptCT_DO for 90 Attr in policy......\n"
    cpabe-encryptCT_DO -o arthur90.txt.ct_do pub_key arthur90.txt epsilon dummy_attribute "trH and gkC and cqF and VcG and Eev and HUu and NPW and bey and xqw and gHf and fem and DnM and rHM and nwA and RZb and rqY and yHy and hYQ and mjk and pTr and Akw and ENB and rtJ and MFY and bjx and BAr and HmF and zzC and VSK and UnN and MHY and HTZ and EvH and Pkv and zKM and Xtc and dJN and jQN and wSG and dZZ and rsp and mMp and wNR and mED and GFn and Gtt and rhT and tvF and Fgy and bQr and nHB and sxH and Kbf and Xvt and SAG and kGg and tpR and UtG and xse and zup and uPT and yDx and uGz and dMM and QXk and kxm and mrB and yDu and xJC and KTk and SYK and UPh and dhS and BNJ and UdB and MGt and KKf and Mre and jNM and dKk and Czj and xST and nTW and MrK and wcp and yQv and DkK and SRv and qMt and PaC"
    
    touch arthur100.txt
    echo "Test for Fahdabe" >> arthur100.txt
    echo -e "\n\n running cpabe-encryptCT_DO for 100 Attr in policy......\n"
    cpabe-encryptCT_DO -o arthur100.txt.ct_do pub_key arthur100.txt epsilon dummy_attribute "WWg and wuW and zah and yAF and sTf and fsS and jEU and qAw and ZMZ and rUe and XFG and hkt and XSW and MVg and Xpy and WkD and Zwp and kXW and SYH and scP and PCb and TrH and GYQ and MXT and Mzy and FeC and CAH and UhG and DmB and RaW and TjY and Ncm and XUS and rbT and vcm and MHd and uGN and dxE and sVa and XCn and psG and FuN and bqW and NNv and ynf and bym and BTe and rSA and NSG and Jzc and DHc and dPN and gBz and kBY and StF and muf and wsM and Ghy and AEu and Nnq and VFg and PVw and mUq and daD and GEy and ZvM and YUr and pvB and VpZ and pfQ and ymP and rKz and nFj and PnH and ZNB and FJZ and ape and Vqk and amm and hKW and zcb and Qvh and dqY and WBQ and NNV and sYr and RfY and dyp and Vvc and TCg and CWa and HzK and RYb and MvU and xPT and GRE and WEb and tqF and BnR and Suh"
    
    echo -e "\n"
    echo -e "\n"


    ########## cpabe-encryptCT_RRD ##########
    # command execution
    echo -e "\n\n running cpabe-encryptCT_RRD for 10 Attr in policy......\n"
    cpabe-encryptCT_RRD pub_key arthur10.txt.ct_do
    
    echo -e "\n\n running cpabe-encryptCT_RRD for 20 Attr in policy......\n"
    cpabe-encryptCT_RRD pub_key arthur20.txt.ct_do
    
    echo -e "\n\n running cpabe-encryptCT_RRD for 30 Attr in policy......\n"
    cpabe-encryptCT_RRD pub_key arthur30.txt.ct_do
    
    echo -e "\n\n running cpabe-encryptCT_RRD for 40 Attr in policy......\n"
    cpabe-encryptCT_RRD pub_key arthur40.txt.ct_do
    
    echo -e "\n\n running cpabe-encryptCT_RRD for 50 Attr in policy......\n"
    cpabe-encryptCT_RRD pub_key arthur50.txt.ct_do
    
    echo -e "\n\n running cpabe-encryptCT_RRD for 60 Attr in policy......\n"
    cpabe-encryptCT_RRD pub_key arthur60.txt.ct_do

    echo -e "\n\n running cpabe-encryptCT_RRD for 70 Attr in policy......\n"
    cpabe-encryptCT_RRD pub_key arthur70.txt.ct_do

    echo -e "\n\n running cpabe-encryptCT_RRD for 80 Attr in policy......\n"
    cpabe-encryptCT_RRD pub_key arthur80.txt.ct_do

    echo -e "\n\n running cpabe-encryptCT_RRD for 90 Attr in policy......\n"
    cpabe-encryptCT_RRD pub_key arthur90.txt.ct_do

    echo -e "\n\n running cpabe-encryptCT_RRD for 100 Attr in policy......\n"
    cpabe-encryptCT_RRD pub_key arthur100.txt.ct_do
    
    echo -e "\n"
    echo -e "\n"

    ########## cpabe-decryptCT_RRD ##########
    # command execution
    
    echo -e "\n\n running cpabe-decryptCT_RRD for 10 Attr in policy......\n"
    cpabe-decryptCT_RRD pub_key DU_Out_key_10 arthur10.txt.ct_do.cpabe decryption_results_10
    
    echo -e "\n\n running cpabe-decryptCT_RRD for 20 Attr in policy......\n"
    cpabe-decryptCT_RRD pub_key DU_Out_key_20 arthur20.txt.ct_do.cpabe decryption_results_20
    
    echo -e "\n\n running cpabe-decryptCT_RRD for 30 Attr in policy......\n"
    cpabe-decryptCT_RRD pub_key DU_Out_key_30 arthur30.txt.ct_do.cpabe decryption_results_30
    
    echo -e "\n\n running cpabe-decryptCT_RRD for 40 Attr in policy......\n"
    cpabe-decryptCT_RRD pub_key DU_Out_key_40 arthur40.txt.ct_do.cpabe decryption_results_40

    echo -e "\n\n running cpabe-decryptCT_RRD for 50 Attr in policy......\n"
    cpabe-decryptCT_RRD pub_key DU_Out_key_50 arthur50.txt.ct_do.cpabe decryption_results_50
    
    echo -e "\n\n running cpabe-decryptCT_RRD for 60 Attr in policy......\n"
    cpabe-decryptCT_RRD pub_key DU_Out_key_60 arthur60.txt.ct_do.cpabe decryption_results_60
    
    echo -e "\n\n running cpabe-decryptCT_RRD for 70 Attr in policy......\n"
    cpabe-decryptCT_RRD pub_key DU_Out_key_70 arthur70.txt.ct_do.cpabe decryption_results_70
    
    echo -e "\n\n running cpabe-decryptCT_RRD for 80 Attr in policy......\n"
    cpabe-decryptCT_RRD pub_key DU_Out_key_80 arthur80.txt.ct_do.cpabe decryption_results_80

    echo -e "\n\n running cpabe-decryptCT_RRD for 90 Attr in policy......\n"
    cpabe-decryptCT_RRD pub_key DU_Out_key_90 arthur90.txt.ct_do.cpabe decryption_results_90

    echo -e "\n\n running cpabe-decryptCT_RRD for 100 Attr in policy......\n"
    cpabe-decryptCT_RRD pub_key DU_Out_key_100 arthur100.txt.ct_do.cpabe decryption_results_100

    echo -e "\n"
    echo -e "\n"

     ########## cpabe-decryptCT_DU ##########
    # command execution

    echo -e "\n\n running cpabe-decryptCT_DU for 10 Attr in policy......\n"
    cpabe-decryptCT_DU pub_key user_key10 arthur10.txt.ct_do arthur10.txt.aes decryption_results_10

    echo -e "\n\n running cpabe-decryptCT_DU for 20 Attr in policy......\n"
    cpabe-decryptCT_DU pub_key user_key20 arthur20.txt.ct_do arthur20.txt.aes decryption_results_20

    echo -e "\n\n running cpabe-decryptCT_DU for 30 Attr in policy......\n"
    cpabe-decryptCT_DU pub_key user_key30 arthur30.txt.ct_do arthur30.txt.aes decryption_results_30

    echo -e "\n\n running cpabe-decryptCT_DU for 40 Attr in policy......\n"
    cpabe-decryptCT_DU pub_key user_key40 arthur40.txt.ct_do arthur40.txt.aes decryption_results_40

    echo -e "\n\n running cpabe-decryptCT_DU for 50 Attr in policy......\n"
    cpabe-decryptCT_DU pub_key user_key50 arthur50.txt.ct_do arthur50.txt.aes decryption_results_50

    echo -e "\n\n running cpabe-decryptCT_DU for 60 Attr in policy......\n"
    cpabe-decryptCT_DU pub_key user_key60 arthur60.txt.ct_do arthur60.txt.aes decryption_results_60

    echo -e "\n\n running cpabe-decryptCT_DU for 70 Attr in policy......\n"
    cpabe-decryptCT_DU pub_key user_key70 arthur70.txt.ct_do arthur70.txt.aes decryption_results_70

    echo -e "\n\n running cpabe-decryptCT_DU for 80 Attr in policy......\n"
    cpabe-decryptCT_DU pub_key user_key80 arthur80.txt.ct_do arthur80.txt.aes decryption_results_80

    echo -e "\n\n running cpabe-decryptCT_DU for 90 Attr in policy......\n"
    cpabe-decryptCT_DU pub_key user_key90 arthur90.txt.ct_do arthur90.txt.aes decryption_results_90

    echo -e "\n\n running cpabe-decryptCT_DU for 100 Attr in policy......\n"
    cpabe-decryptCT_DU pub_key user_key100 arthur100.txt.ct_do arthur100.txt.aes decryption_results_100

    echo -e "\n"
    echo -e "\n"
fi