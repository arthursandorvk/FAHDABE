#!/bin/bash

if [ 1 ]; then
	
	echo -e "Launching the FAHDABE project with 3 attribute authorities in the system... \n"
	sleep 2

	echo -e "\n\n running cpabe-setup...... \n\n"

	# command usage
	cpabe-setup --usage
	sleep 2

	# command execution
	cpabe-setup
	
	if [ $? -eq 0 ]; then
		echo -e "\n\n cpabe-setup deployed with success ! \n\n"
	else
		echo -e "\n Error when deploying cpabe-setup... Kindly check \n"
		exit 1
	fi

	# sleep transition
	sleep 2

	#-------------------------------------------------------------------

	echo -e "\n\n running cpabe-keygen0......\n\n"

	# command usage
	cpabe-keygen0 --usage
	sleep 2
	
	# command execution
	cpabe-keygen0 $publicKey $epsilon

	if [ $? -eq 0 ]; then
		echo -e "\n\n cpabe-keygen0 deployed with success ! \n\n"
	else
		echo -e "\n Error when deploying cpabe-keygen0... Kindly check \n"
		exit 1
	fi

	# sleep transition
	sleep 2
	
	#-------------------------------------------------------------------
	
	echo -e "\n\n running cpabe-keygen1......\n\n"

	# command usage
	cpabe-keygen1 --usage
	sleep 2

	# command execution
	cpabe-keygen1 $publicKey $masterKey $du_blindFile $dummy
	 
	if [ $? -eq 0 ]; then
		echo -e "\n\n cpabe-keygen1 deployed with success ! \n\n"	
	else
		echo -e "\n Error when deploying cpabe-keygen1... Kindly check \n"
		exit 1
	fi

	# sleep transition
	sleep 2

	#-------------------------------------------------------------------

	echo -e "\n\n running cpabe-hide......\n\n"

	# command usage
	cpabe-hide --usage
	sleep 2

	# command execution
	echo -e "running cpabe-hide for the first set of attributes $userAttr1......\n"
	cpabe-hide $publicKey $doKey $userAttr1 -o $hiddenAttrFile1 
	if [ $? -eq 1 ]; then
		echo -e "\n Error when deploying cpabe-hide with $doKey, $userAttr1 and $hiddenAttrFile1... Kindly check \n"
		exit 1
	fi

	echo -e "running cpabe-hide for the second set of attributes $userAttr2......\n"
	cpabe-hide $publicKey $doKey $userAttr2 -o $hiddenAttrFile2 
	if [ $? -eq 1 ]; then
		echo -e "\n Error when deploying cpabe-hide with $doKey, $userAttr2 and $hiddenAttrFile2... Kindly check \n"
		exit 1
	fi

	echo -e "running cpabe-hide for the third set of attributes $userAttr3......\n"
	cpabe-hide $publicKey $doKey $userAttr3 -o $hiddenAttrFile3 
	if [ $? -eq 1 ]; then
		echo -e "\n Error when deploying cpabe-hideDU_ATTR with $doKey, $userAttr3 and $hiddenAttrFile3... Kindly check \n"
		exit 1
	fi

	echo -e "\n\n cpabe-hide deployed with success ! \n\n"

	# sleep transition
	sleep 2

	#-------------------------------------------------------------------

	echo -e "\n\n running cpabe-keygen2 (with 3 Attribute Authorities)......\n\n"

	# command usage
	cpabe-keygen2 --usage
	sleep 2

	# command execution
	echo -e "running cpabe-keygen2 for AA1 (the first AA)......\n"
	cpabe-keygen2 $publicKey $hiddenAttrFile1 -o $AAFile1
	if [ $? -eq 1 ]; then
		echo -e "\n Error when deploying cpabe-keygen2 with $hiddenAttrFile1 and $AAFile1 ... Kindly check \n"
		exit 1
	fi

	echo -e "running cpabe-keygen2 for AA2 (the second AA)......\n"
	cpabe-keygen2 $publicKey $hiddenAttrFile2 -o $AAFile2
	if [ $? -eq 1 ]; then
		echo -e "\n Error when deploying cpabe-keygen2 with $hiddenAttrFile2 and $AAFile2 ... Kindly check \n"
		exit 1
	fi

	echo -e "running cpabe-keygenAA for AA3 (the third AA)......\n"
	cpabe-keygen2 $publicKey $hiddenAttrFile3 -o $AAFile3
	if [ $? -eq 1 ]; then
		echo -e "\n Error when deploying cpabe-keygen2 with $hiddenAttrFile3 and $AAFile3 ... Kindly check \n"
		exit 1
	fi

	echo -e "\n\n cpabe-keygen2 deployed with success ! \n\n"

	# sleep transition
	sleep 2

	#-------------------------------------------------------------------
		
	echo -e "\n\n running cpabe-keygen3 (with 3 Attribute Authorities)......\n\n"

	# command usage
	cpabe-keygen3 --usage
	sleep 2

	# command execution
	cpabe-keygen3 $publicKey $AAFile1 $AAFile2 $AAFile3 -o $rrdKeyFile
	 
	if [ $? -eq 0 ]; then
		echo -e "\n\n cpabe-keygen3 deployed with success ! \n\n"
	else
		echo -e "\n Error when deploying cpabe-keygen3 with $AAFile1, $AAFile2 and $AAFile3 ... Kindly check \n"
		exit 1
	fi

	# sleep transition
	sleep 2

	#-------------------------------------------------------------------

	echo -e "\n\n running cpabe-keygen4......\n\n"

	# command usage
	cpabe-keygen4 --usage
	sleep 2

	cpabe-keygen4 $publicKey $doKey $rrdKeyFile -o $userKeyFile
	 
	if [ $? -eq 0 ]; then
		echo -e "\n\n cpabe-keygen4 deployed with success ! \n\n"
	else
		echo -e "\n Error when deploying cpabe-keygen4 with $doKey, $rrdKeyFile and $userKeyFile ... Kindly check \n"
		exit 1
	fi

	# sleep transition
	sleep 2

	#-------------------------------------------------------------------
		
	echo -e "\n\n running cpabe-encrypt1......\n\n"

	# initializing the file fahdabe.txt
	touch $plaintextFile && echo "Welcome to test FAHDABE ! very pleased to have you around" >> $plaintextFile

	# command execution
	cpabe-encrypt1 $publicKey $plaintextFile $epsilon_DO_paramFile $dummy $accessPolicy
	 
	if [ $? -eq 0 ]; then
		echo -e "\n\n cpabe-encrypt1 deployed with success ! \n\n"
	else
		echo -e "\n Error when deploying encrypt1 with $plaintextFile, $dummy and $accessPolicy ... Kindly check \n"
		exit 1
	fi

	# sleep transition
	sleep 2

	#-------------------------------------------------------------------

	echo -e "\n\n running cpabe-encrypt2......\n\n"

	# command usage
	cpabe-encrypt2 --usage
	sleep 2

	# command execution
	cpabe-encrypt2 $publicKey "$plaintextFile.ct_do"
	 
	if [ $? -eq 0 ]; then
		echo -e "\n\n cpabe-encrypt2 deployed with success ! \n\n"
	else
		echo -e "\n Error when deploying encrypt2 with $plaintextFile.ct_do ... Kindly check \n"
		exit 1
	fi

	# sleep transition
	sleep 2

	#-------------------------------------------------------------------
	
	echo -e "\n\n running cpabe-transform1......\n\n"

	# command usage
	cpabe-transform1 --usage
	sleep 2

	# command execution
	cpabe-transform1 $publicKey $publicUserSubKeyFile $rrdCiphertextFile $decryptResultFile -o `echo $rrdCiphertextFile | cut -d '.' -f1-3`

	if [ $? -eq 0 ]; then
		echo -e "\n\n cpabe-transform1 deployed with success ! \n\n"
	else
		echo -e "\n Error when deploying transform1 with $publicUserSubKeyFile, $rrdCiphertextFile, $decryptResultFile and `echo $rrdCiphertextFile | cut -d '.' -f1-3`  ... Kindly check \n"
		exit 1
	fi

	#-------------------------------------------------------------------
	
	echo -e "\n\n running cpabe-transform2......\n\n"

	# command usage
	cpabe-transform2 --usage
	sleep 2

	# command execution
	 cpabe-transform2 $publicKey $userKeyFile `echo $rrdCiphertextFile | cut -d '.' -f1-3` "$plaintextFile.aes" $decryptResultFile -o `echo $rrdCiphertextFile | cut -d '.' -f1-2`

	if [ $? -eq 0 ]; then
		echo -e "\n\n cpabe-transform2 deployed with success ! \n\n"
	else
		echo -e "\n Error when deploying transform2 with $userKeyFile, $intermediateCiphertextFile, $plaintextFile.aes, $decryptResultFile, and $decryptedContentFile  ... Kindly check \n"
		exit 1
	fi

	# sleep transition
	sleep 2

	#-------------------------------------------------------------------

else
	echo -e "Error Launching the FAHDABE project !!! ... \n"
	exit 1
	
fi
