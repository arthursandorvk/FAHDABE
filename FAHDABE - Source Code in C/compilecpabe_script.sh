#!/bin/bash
export G_SLICE=always-malloc

cd "/home/summer/Documents/Github16November2024/libbswabe-0.9_FAHDABE"
make clean && make && sudo make install

if [ $? -eq 0 ]; then
	cd "/home/summer/Documents/Github16November2024/cpabe-0.11_FAHDABE"
	make clean && make && sudo make install
	export G_SLICE=always-malloc
	echo -e "FAHDABE project deployed successfully ! \n"

	# Project deployment
	#-------------------------------------------------------------------
	#----------------------------cpabe-setup----------------------------
	#-------------------------------------------------------------------
	echo -e "running cpabe-setup......\n"

	cpabe-setup
	
	if [ $? -eq 0 ]; then
		echo -e "end of cpabe-setup......\n"
	else
		echo -e "cpabe-setup failed with an error !... please check \n"
		exit 1
	fi
	#-------------------------------------------------------------------

	
	#-------------------------------------------------------------------
	#----------------------------cpabe-keygenEpsilon--------------------
	#-------------------------------------------------------------------
	echo -e "running cpabe-epsilon......\n"

	# attribute masking value epsilon
	epsilon="epsilon"
	
	cpabe-keygen0 pub_key $epsilon

	if [ $? -eq 0 ]; then
		echo -e "end of cpabe-keygen0......\n"
		
	else
		echo -e "cpabe-keygen0 failed with an error !... please check \n"
		exit 1
	fi
	#-------------------------------------------------------------------

	# the user id
	user_id="id1"
	
	#-------------------------------------------------------------------
	#----------------------------cpabe-keygenDO----------------------------
	#-------------------------------------------------------------------
	echo -e "running cpabe-keygenDO......\n"
	
	#dummy attribute value
	dummy_attr="dummy"

	#name of file to store the DO blinding parameter for attributes
	du_blind_file="du_blind"

	cpabe-keygen1 pub_key master_key $user_id $dummy_attr
	 
	if [ $? -eq 0 ]; then
		echo -e "end of cpabe-keygenDO......\n"
	else
		echo -e "cpabe-keygenDO failed with an error !... please check \n"
		exit 1
	fi
	#-------------------------------------------------------------------



	#-------------------------------------------------------------------
	#----------------------------cpabe-hideDU_ATTR----------------------------
	#-------------------------------------------------------------------
	echo -e "running cpabe-hide with 2 sets of attributes managed by AA1 and AA2, respectively......\n"

	# the first set of attributes to hide managed by a specific AA
	cpabe-hide pub_key DO_key "A" "B" "C" -o A1
	if [ $? -eq 0 ]; then
		# do nothing
		pass
	else
		echo -e "cpabe-hideDU_ATTR failed with an error !... please check \n"
		exit 1
	fi

	# the second set of attributes to hide managed by a specific AA
	cpabe-hide pub_key DO_key "hire_date" "876868" -o A2
	if [ $? -eq 0 ]; then
		echo -e "end of cpabe-hideDU\_ATTR......\n"
	else
		echo -e "cpabe-hideDU_ATTR failed with an error !... please check \n"
		exit 1
	fi
	#-------------------------------------------------------------------


	#-------------------------------------------------------------------
	#----------------------------cpabe-keygenAA-------------------------
	#-------------------------------------------------------------------
	echo -e "running cpabe-keygenAA for AA1 (the first AA)......\n"


	cpabe-keygen2 -o AA1_key pub_key A1 $user_id
	if [ $? -eq 0 ]; then
		echo -e "end of cpabe-keygenAA......\n"
	else
		echo -e "cpabe-keygenAA failed with an error !... please check \n"
		exit 1
	fi

	echo -e "running cpabe-keygenAA for AA2 (the second AA)......\n"

	cpabe-keygen2 -o AA2_key pub_key A2 $user_id
	if [ $? -eq 0 ]; then
		# do nothing
		pass
	else
		echo -e "cpabe-keygenAA failed with an error !... please check \n"
		exit 1
	fi
	#-------------------------------------------------------------------



	#-------------------------------------------------------------------
	#---------cpabe-keygenRRD(Resource-Rich Device)---------------------
	#-------------------------------------------------------------------
	
	echo -e "running cpabe-keygenRRD(Resource-Rich Device)......\n"

	cpabe-keygen3 pub_key $du_blind_file AA1_key AA2_key 
	 
	if [ $? -eq 0 ]; then
		echo -e "end of cpabe-keygenRRD......\n"
	else
		echo -e "cpabe-keygenRRD failed with an error !... please check \n"
		exit 1
	fi
	#-------------------------------------------------------------------

	
	#-------------------------------------------------------------------
	#--------------------------cpabe-keygenDU---------------------------
	#-------------------------------------------------------------------
	echo -e "running cpabe-keygenDU......\n"

	# name of the DO_key file
	do_key_file="DO_key"

	# name of the RRD key file
	rrd_key_file="rrd_key"

	# name of the DU_Out_key file
	du_out_key_file="DU_Out_key"

	cpabe-keygen4 pub_key $do_key_file $rrd_key_file $du_out_key_file $user_id
	 
	if [ $? -eq 0 ]; then
		echo -e "cpabe-keygenDU Okay...\n"
		echo -e "The user secret key has been written by default to user_key...\n"
		`sleep 2`
		echo "#-----------------------------------------------------------------------"
		echo "#--------------------------End of cpabe-keygenDU------------------------"
		echo -e "#-------------------------------------------------------------------\n"
	
	else
		echo -e "An error occured with cpabe-keygenDU(Resource-Rich Device)... please investigate \n"
		exit 1
	fi
	#-------------------------------------------------------------------


	#-------------------------------------------------------------------
	#----------------------------cpabe-encryptCT_DO---------------------
	#-------------------------------------------------------------------
	echo "#-------------------------------------------------------------------"
	echo "#----------------------------cpabe-encryptCT_DO---------------------"
	echo -e "#-------------------------------------------------------------------\n"
	
	policy="A and (B or C) and (hire_d or 876868)"

	echo -e "#---------We adopt the default access policy---> $policy \n"
		
	echo -e "running cpabe-encryptCT_DO......\n"

	echo -n "plaintext file initialization (arthur.txt)...."
	sleep 2

	touch "arthur.txt" && echo "Welcome Mr Arthur to Your Home ! very pleased to have you around" >> "arthur.txt"

	echo -e "Done ! \n" 

	echo "--------------------------------------------------------------------"
	echo "---------------------------Name of the input file-------------------"
	echo -e "--------------------------------------------------------------------\n"

	echo -n "Name of the input file (in directory: `pwd`) --------------> "
	read input_file


	# For a longer policy, you need to adjust the size of buffers in Popen commands
	cpabe-encrypt1 pub_key $input_file $epsilon $dummy_attr "A and (B or C) and (hire_date or 876868)"
	
	#'A and (B or C) and (hire_date or 876868)'
	 	 

	if [ $? -eq 0 ]; then
		echo -e "cpabe-encrypt1 Okay...\n"
		echo "#----------------- --------------------------------------------------"
		echo "#---------------------End of cpabe-encrypt1---------------------"
		echo -e "#-------------------------------------------------------------------\n"
	
	else
		echo -e "An error occured with cpabe-encrypt1... please investigate \n"
		exit 1
	fi
	#-------------------------------------------------------------------


	#-------------------------------------------------------------------
	#----------------------------cpabe-encrypt2---------------------
	#-------------------------------------------------------------------
	echo "#-------------------------------------------------------------------"
	echo "#------cpabe-encrypt2 (Resource-rich Device)---------------------"
	echo -e "#---------------------------------------PUBLIC_USER_SUBKEY_FILE----------------------------\n"
	
	#parsed_policy="[539,508,517,472,624,735,221,991] [971,987,493,75,819,831,162,211] 1of2 [438,142,256,307,880,59,40,903]
 	#[718,923,626,112,382,457,403,821] 1of2 [914,729,446,1019,772,481,942,258] 3of3"
	#
	#echo -e "#---------The converted access policy is ---> $parsed_policy \n"
		
	echo -e "running cpabe-encrypt2 (Resource-rich Device)......\n"

	echo "--------------------------------------------------------------------"
	echo "-----------Name of the input file obtained from DO encryption-------------------"
	echo -e "----------------------------------------------------------------\n"

	echo -n "Name of the input file that ends with \".ct_do\" (in directory: `pwd`) --------------> "
	read input_file

	cpabe-encrypt2 pub_key $input_file
	 
	if [ $? -eq 0 ]; then
		echo -e "cpabe-encryptCT2 (Resource-rich Device) Okay...\n"
		echo -e "The result has been written into $inputfile.cpabe \n"
		`sleep 2`
		echo "#-------------------------------------------------------------------"
		echo "#-----End of cpabe-encrypt2 (Resource-rich Device)-------------"
		echo -e "#---------------------------------------------------------------\n"
	
	else
		echo -e "An error occured with cpabe-encrypt2... please investigate \n"
		exit 1
	fi
	#-------------------------------------------------------------------
	

	#-------------------------------------------------------------------
	#----------cpabe-decryptCT_RRD(Resource-Rich device)----------------
	#-------------------------------------------------------------------
	echo "#-------------------------------------------------------------------"
	echo "#----------------------------cpabe-decryptCT_RRD---------------------"
	echo -e "#----------------------------------------------------------------\n"
		
	echo -e "running cpabe-transform1......\n"

	echo "-------------------------------------------------------------------------"
	echo "----Name of the .cpabe ciphertext input file (format .ct_do.cpabe)-------"
	echo -e "--------------------------------------------------------------------\n"

	echo -n "Name of the input ciphertext file (in directory: `pwd`) --------------> "
	read input_file

	cpabe-transform1 pub_key DU_Out_key $input_file decryption_results
	 
	if [ $? -eq 0 ]; then
		echo -e "cpabe-transform1 Okay...\n"
		
		echo -e "if the decryption worked, the resulting file will be written with extension .ct.do, which must go through the final 			stage of user local decryption \n"

		echo "#-------------------------------------------------------------------"
		echo "#---------------------End of cpabe-transform1---------------------"
		echo -e "#-------------------------------------------------------------------\n"
	
	else
		echo -e "An error occured with cpabe-transform1... please investigate \n"
		exit 1
	fi
	#-------------------------------------------------------------------

	
	#-------------------------------------------------------------------
	#---------------------------cpabe-transform2----------------------
	#-------------------------------------------------------------------
	echo "#-------------------------------------------------------------------"
	echo "#----------------------------cpabe-transform2-----------------------"
	echo -e "#----------------------------------------------------------------\n"
		
	echo -e "running cpabe-transform2......\n"

	echo "-------------------------------------------------------------------------"
	echo "------------------Name of the user secret key input file ----------------"
	echo -e "--------------------------------------------------------------------\n"

	echo -n "Name of the user secret key input file (in directory: `pwd`) --------------> "
	read input_userKey_file


	echo "-------------------------------------------------------------------------"
	echo "----Name of the DO ciphertext input file (format .ct_do)-------"
	echo -e "--------------------------------------------------------------------\n"

	echo -n "Name of the input DO ciphertext file (in directory: `pwd`) --------------> "
	read DO_input_file


	echo "-------------------------------------------------------------------------"
	echo "------Name of the AES Decrypted File (in the format .aes)----------------"
	echo -e "--------------------------------------------------------------------\n"

	echo -n "Name of the the AES Decrypted File as input file (in directory: `pwd`) --------------> "
	read aes_decrypted_file


	echo "-------------------------------------------------------------------------"
	echo "--------------------Name of the Plaintext Decrypted File ----------------"
	echo -e "--------------------------------------------------------------------\n"

	echo -n "Name of the Plaintext Decrypted File (in directory: `pwd`) --------------> "
	read plaintext_decrypted_file


	echo -e "cpabe-decryptCT_DU takes as well the result from the outsourced decryption computed by the resource-rich device, the 		resulting AES encryption of the original message: $aes_decrypted_file, and the name of the plaintext file to be output. 
	The former result is stored into decryptNode_Result.arsanvkabe \n" 

	 cpabe-transform2 pub_key $input_userKey_file $DO_input_file $RRD_input_file $du_blind_file $aes_decrypted_file  decryption_results -o $plaintext_decrypted_file


	# cpabe-decryptCT_DU pub_key user_key arthur.txt.ct_do arthur.txt.aes decryptNode_Result.arsanvkabe arthur.txt.aes_plt -o arthur_DECRYPTED5.txt

	 
	if [ $? -eq 0 ]; then
		echo -e "cpabe-decryptCT_DU Okay...\n"
		
		echo -e "if the local decryption at the user side worked, the resulting file (plaintext) will be written without 			extension .ct.do (will have the original name of the file) \n"

		echo "#-------------------------------------------------------------------"
		echo "#---------------------End of cpabe-transform2-----------------------"
		echo -e "#-------------------------------------------------------------------\n"
	
	else
		echo -e "An error occured with cpabe-transform2... please investigate \n"
		exit 1
	fi
	#-------------------------------------------------------------------


else
	echo -e "A problemed occured during the deployment of ABE project \n"
	exit 1
	
fi


