/*
 * keygen4.c
 *
 *  Created on: Nov 29, 2023
 *      Author: Arthur Sandor
 */
/*
 * This code aims to construct the complete user secret key and will be executed by the user.
 * First the user will fetch the Data owner secret key component D and later will its RRD key 
 * that contains key parameters for each hidden attribute in its attribute set. 
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <glib.h>
#include <pbc.h>
#include <assert.h>
#include <pbc_random.h>
#include <openssl/sha.h>

#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"
#include "keygen4.h"



char* usage=
"Usage: cpabe-keygen4 [OPTION ...] PUB_KEY DO_KEY RRD_KEY DU_OUT_KEY USER_GID \n"
"\n"
"Generate the complete user secret key with the RRD KEY file, the DO KEY file, \n"
"the DU_OUT_KEY file, the user GID in USER_GID, and using the public key PUB_KEY.\n" 
"the complete user secret key output for the complete user secret key will be written to the file \n"
"'user_key' unless the -o option is specified. The user public subkey will be written into the file DU_OUT_KEY \n"
"\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";


char* pub_file = 0; /* file containing the public key */

char* RRD_file = 0; /* file containing the RRD key aided by the Resource-Rich Device*/ 

char* DO_file = 0; /* file containing the key issued by the Data Owner */

char* DU_Out_Key_file = 0; /* file to contain the user public subkey to be used for outsourced decryption */

char* user_gid = 0; /* variable containing the user GID */

char* out_file = USER_SECRET_KEY_FILE; /* file to hold the complete user secret key */

bswabe_pub_t *pub = 0; /* pointer on the public key */

/* variables to hold the start and end time */
clock_t start=0;
clock_t end=0;

/* time difference time_diff */
clock_t time_diff=0;


gint comp_string( gconstpointer a, gconstpointer b)
{
	return strcmp(a, b);
}

void parse_args( int argc, char** argv )
{
	int i;

	for( i = 1; i < argc; i++ )
		if(     !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(CPABE_VERSION, "-keygenDU");
			exit(0);
		}
		else if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") )
		{
			if( ++i >= argc )
				die(usage);
			else
				out_file = argv[i];
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
        	else if( !DO_file )
		{
			DO_file = argv[i];
		}
		else if( !RRD_file )
		{
			RRD_file = argv[i];
		}
		else if( !DU_Out_Key_file )
		{
			DU_Out_Key_file = argv[i];
		}
		else if( !user_gid )
		{
			user_gid = argv[i];
		}
          	 else
			die(usage);

	if(  !pub_file ||!DO_file || !RRD_file || !DU_Out_Key_file || !user_gid )
		die(usage);
}


//our main fucntion
int main(int argc, char **argv)
{
	/* Start the timer */
	start = clock();

	arsanvkabe_prv_user_t *userSKey=0; /* pointer  on complete user secret key to be returned */

	user_RRD_t *DU_Out_Key=0; /* public user subkey pointer */

	parse_args( argc, argv ); 

	pub = bswabe_pub_unserialize(load_gbyte_array(pub_file),1); //the pointer on the public key
	

	/* Initializing complete user secret key*/
	userSKey = (arsanvkabe_prv_user_t*)malloc(sizeof(arsanvkabe_prv_user_t));

	/* Initializing public user subkey */
    DU_Out_Key = (user_RRD_t*) malloc(sizeof(user_RRD_t)); 
	DU_Out_Key->rrd_key = 0;
    element_init_G1(DU_Out_Key->dr, pub->p);
	element_init_G1(DU_Out_Key->d_attd, pub->p);
	element_init_G1(DU_Out_Key->t_attd, pub->p);


	/* Unserializing DO Key */
	GByteArray *content_DO_Gbyte_Array=0;
    content_DO_Gbyte_Array = load_gbyte_array(DO_file);
	int offset_do;
	offset_do = 0;


	/* assignment of DO key component in the complete user secret key */
    userSKey->D = arsanvkabe_prv_do_unserialize(pub, content_DO_Gbyte_Array, 1);

	
	/* Unserializing RRD Key */
    GByteArray *RRD_content=0;	
    RRD_content = load_gbyte_array(RRD_file);
	int offset_RRD;
	offset_RRD = 0;


	/* assignment of RRD key component in the complete user secret key */
    userSKey->U = arsanvkabe_prv_rrdKey_unserialize(pub, RRD_content, 0);


	/* assignment of RRD key component in the public user subkey */
    DU_Out_Key->rrd_key = arsanvkabe_prv_rrdKey_unserialize(pub, RRD_content, 1); /* empty content of RRD_content GByteArrray* */


	/* computation of DU_Out_Key->dr using user GID */
	element_t gamma;
	element_init_Zr(gamma, pub->p);
	element_from_string(gamma, user_gid);

	element_pow_zn(DU_Out_Key->dr, pub->f, gamma);


	/* getting parameters related to the dummy attribute */
	arsanvkabe_prv_comp_t dummy_Structure = g_array_index(userSKey->D->dummy_attr_array, arsanvkabe_prv_comp_t, 0);
	

	/* assignment of DU_Out_Key->d_attd after unserializing the DO Key component */
	element_set(DU_Out_Key->d_attd, dummy_Structure.d); 

	/* assignment of DU_Out_Key->t_attd after unserializing the DO Key component */
	element_set(DU_Out_Key->t_attd, dummy_Structure.dp);


    /* We serialize DU_Out_Key in a file */
    GByteArray* b_new;
    b_new = g_byte_array_new();
    b_new = arsanvkabe_User_RRD_subKey_serialize(DU_Out_Key);
    //store_gbyte_array(b_new, PUBLIC_USER_SUBKEY_FILE);
	store_gbyte_array(b_new, DU_Out_Key_file);


	/* serialize complete user secret key userSKey in a file */
	GByteArray* b_userSK=0;
	b_userSK = g_byte_array_new();
	b_userSK = arsanvkabe_prv_userSK_serialize(userSKey);
	store_gbyte_array( b_userSK, out_file);
	
	/* freeing some memory*/
	user_RRD_t_free(DU_Out_Key);
	arsanvkabe_prv_user_t_free(userSKey);
	g_byte_array_free(b_new, 1);
	g_byte_array_free(b_userSK, 1);
	arsanvkabe_prv_comp_t_free(&(dummy_Structure));

	/* Timing the Experiments */
	time_diff = (clock() - start);
	
	/* clock drift report */
	printf("Time taken by cpabe-keygen4 %f ms (milliseconds)\n\n",((double) (time_diff*1000) / CLOCKS_PER_SEC));
	
	return 0;
}
