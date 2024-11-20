#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include <time.h>
#include <openssl/rand.h> 

#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"

#include "encrypt1.h"
#include <assert.h>


#define AES_BLOCK_SIZE 16

char* usage =
"Usage: cpabe-encrypt1 [OPTION ...] PUB_KEY INPUT_FILE EPSILON DUMMY_ATTRIBUTE [POLICY]\n"
"\n"
"Empower the Data owner to realize the first stage encryption on INPUT_FILE.\n" 
"Through this operation, DO anonymizes the access policy POLICY using \n"
"epsilon masking factor in EPSILON (with additive homorphic hashing through H2())\n" 
" As a result, the resource-rich device learns nothing about the values \n"
"of attributes in the access policy. \n"
"The encrypted file (DO ciphertext) leverages the dummy attribute DUMMY_ATTRIBUTE.\n"
" DO ciphertext will be written as INPUT_FILE.ct.do unless\n"
"the -o option is used. The original file will be removed if -k is not invoked.\n"
"If POLICY is not specified, the policy will be read from stdin.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -k, --keep-input-file    don't delete original file\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char* pub_file = 0;	/* file containing public key */
char* in_file  = 0; /* plaintext file */
char* dummy_attribute_value = 0; /* dummy attribute value */
char* out_file = 0; /*output DO ciphertext file */
int   keep     = 0; /* whether to keep the plaintext file*/
char* epsilon_value = 0; /* the value of the attribute hidding factor epsilon*/

char* policy = 0;

/* clock start global variable */
clock_t start=0;

/* clock elapsed time (global) variable */
clock_t time_diff=0;


void parse_args( int argc, char** argv )
{
	int i;

	for( i = 1; i < argc; i++ )
		if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(CPABE_VERSION, "-encryptCT_DO");
			exit(0);
		}
		else if( !strcmp(argv[i], "-k") || !strcmp(argv[i], "--keep-input-file") )
		{
			keep = 1;
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
		else if( !in_file )
		{
			in_file = argv[i];
		}
		else if ( !epsilon_value )
		{
			epsilon_value = argv[i];
		}
		else if( !dummy_attribute_value )
		{
			dummy_attribute_value = argv[i];
		}
		else if( !policy )
		{
			policy = parse_policy_lang(argv[i]); /* parsing access policy and hiding attribute values */

			/* Writing the access policy in the designated file */
		}
		else
			die(usage);

	if( !pub_file || !in_file || !epsilon_value || !dummy_attribute_value )
		die(usage);


	if( !policy )
		policy = parse_policy_lang(suck_stdin()); /* could parse and hide policy provided through stdin */
}


int main( int argc, char** argv )
{
	start = clock();	


	bswabe_pub_t* pub; //the public key of the original construction
	
	GByteArray* plaintext_file_bytearray; /* GByteArray containing plaintext file content */
	
	GByteArray* output_aes_enc_bytearray; /* Aes encrypted content of the plaintext file */
	
	arsanvkabe_cph_DO_t* CT_DO; /* pointer on DO ciphertext */

	char* dummy_attribute_digest = 0; /* the hidden value of the dummy attribute */

	element_t dummy_attribute_element; /* the G1 group element corresponding to the hidden dummy attribute value */
	
	element_t m; /* Aes key seed */ 


	/* begin parameters procesing */
	parse_args(argc, argv);

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	

	/* processing the hidden access policy */
	// Writing down the policy in a file to satisfy implementation requirements of H2()
	FILE *file_policy = fopen(POLICY_FILE_NAME, "w");
	if (file_policy == NULL)
	{
		die("Error opening file %s !", POLICY_FILE_NAME);
	}
	/* file to host the access policy appears valid */
	/* writing the hidden access policy */
	fwrite(policy, sizeof(char), strlen(policy), file_policy);
	/* close the file */
	fclose(file_policy);

	/* compute the digest of dummy attribute value: H2(dummy attribute + epsilon) */
	dummy_attribute_digest = compute_Lthash_Add_inputs_return_string(epsilon_value, dummy_attribute_value);

	
	/* derive element_t from the hidden dummy attribute expression */
	element_t dummy_attribute_Zp;
	element_init_Zr(dummy_attribute_Zp, pub->p);
	element_from_string(dummy_attribute_Zp,dummy_attribute_digest );
	

	element_init_G2(dummy_attribute_element, pub->p);
	//element_from_string(dummy_attribute_element, dummy_attribute_digest);
	element_pow_zn(dummy_attribute_element, pub->gp, dummy_attribute_Zp);	
	
	printf("Before calling encrypt1 in core.c\n\n");

	/* Construction of the DO ciphertext */
	if( !(CT_DO = arsanvkabe_encrypt1(pub, m, policy, dummy_attribute_element))) 
		die("%s", bswabe_error());
	

	/* Loading plaintext file content */ 
	plaintext_file_bytearray = load_gbyte_array(in_file);
	int file_len;
	file_len = plaintext_file_bytearray->len;

	/* initializing GByteArray to contain Aes encryption of the plaintext file */
	output_aes_enc_bytearray = g_byte_array_new();
	
	/* encrypting plaintext file */
	output_aes_enc_bytearray = aes_128_cbc_encrypt(plaintext_file_bytearray, m); 

	/* Name of the file containing the Aes encryption of the plaintext file */
	char* output_aes_enc_filename=0;
	output_aes_enc_filename = g_strdup_printf("%s%s", in_file, AES_ENCRYPTED_FILE_EXTENSION);

	/* Storing Aes encrypted content of the plaintext file */	
	store_gbyte_array( output_aes_enc_bytearray, output_aes_enc_filename);

	
	/* Serializing the DO ciphertext structure*/
	GByteArray* output_CT_DO_byteArray;
	output_CT_DO_byteArray = arsanvkabe_cph_DO_serialize(CT_DO);
	
	/* processing the output file */
	if (out_file == 0)
	{
		out_file = g_strdup_printf("%s%s", in_file, DO_CIPHERTEXT_EXTENSION);
	}

	/* writing the content of CT_DO */
	store_gbyte_array( output_CT_DO_byteArray, out_file);
	

	/* Showcasing the parsed and hidden access policy */
	printf("this is the parsed and hidden access policy %s \n \n", CT_DO->p);


	//-------------------------------------------------------------------------

	/* freeing some memory */
	g_byte_array_free(output_CT_DO_byteArray, 1);
	arsanvkabe_cph_do_free(CT_DO);
	g_byte_array_free(output_aes_enc_bytearray, 1);
	g_byte_array_free(plaintext_file_bytearray, 1);
	element_clear(m); /*canceling the Aes key seed (or Aes-CBC IV) */


	/* Whether to keep the original plaintext file */
	if( !keep )
		unlink(in_file);


	/* Timing the experiment */
	time_diff = (clock() - start);
	
	/* clock drift report */
	printf("Time taken by cpabe-encrypt1 %f ms (milliseconds)\n\n",((double) (time_diff*1000) / CLOCKS_PER_SEC));
		
	
	return 0;
}
