#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include <time.h>

#include "policy_lang.h"
#include "bswabe.h"
#include "common.h"
#include "transform2.h"


char* usage =
"Usage: cpabe-transform2 [OPTION ...] PUB_KEY  USER_KEY_FILE  DO_CIPHERTEXT_FILE  AES_ENCRYPTED_PLAINTEXT_FILE RRD_DECRYPT_RESULT_FILE \n"
"\n"

"Decrypt the ciphertext AES_ENCRYPTED_PLAINTEXT_FILE that contains the AES encryption of the original data \n"
"using the complete user secret key in USER_KEY_FILE, the decryption results from the resource-rich device \n"
"in RRD_DECRYPT_RESULT_FILE, and assuming the public key PUB_KEY. The AES secret key is recovered by first \n"
"verifying witness data in DO_CIPHERTEXT_FILE, then extracting the secret key upon successful verification. \n"
"cpabe-decryptCT_DU outputs the plaintext data or nothing useful."
"\n" 
" If the name of FILE is original_name.ct_do, the decrypted file will be written as 'original_name'. \n" 
" The DO_CIPHERTEXT_FILE will be removed unless the use of the -k option. The -o option overiddes "
" the name of the plaintext to be recovered. \n" 
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -k, --keep-input-file    don't delete original file\n\n"
" -o, --output FILE        write output to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
/* " -s, --no-opt-sat         pick an arbitrary way of satisfying the policy\n" */
/* "                          (only for performance comparison)\n\n" */
/* " -n, --naive-dec          use slower decryption algorithm\n" */
/* "                          (only for performance comparison)\n\n" */
/* " -f, --flatten            use slightly different decryption algorithm\n" */
/* "                          (may result in higher or lower performance)\n\n" */
/* " -r, --report-ops         report numbers of group operations\n" */
/* "                          (only for performance evaluation)\n\n" */
"";


char* pub_file = 0; /* file containing the public key structure */
char* user_key_file = 0; /* file containing the user secret key */
char* DO_Cph_file = 0; /* file containing the DO ciphertext */
char* decryptNode_Result_File =0; /* file containing decryption results from RRD */
char* aes_plaintext_file =0; /* file to contain the AES encrypted version of the original plaintext */ 
char* plaintext_file =0; /* file containing the AES decrypted content of the plaintext data */
int   keep = 0; /* whether to keep the DO ciphertext file*/



/* Global variables to hold the start and end time */
clock_t start=0;
clock_t end=0;

/* time difference time_diff */
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
			printf(CPABE_VERSION, "-decryptCT_DU");
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
				plaintext_file = argv[i];
		}
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		else if( !user_key_file )
		{
			user_key_file  = argv[i];
		}
		else if( !DO_Cph_file )
		{
			DO_Cph_file = argv[i];
		}
		else if( !aes_plaintext_file )
		{
			 aes_plaintext_file = argv[i];
		}
		else if( !decryptNode_Result_File )
		{
			decryptNode_Result_File = argv[i];
		}
		else
			die(usage);

	if( !pub_file || !user_key_file || !DO_Cph_file || !aes_plaintext_file || !decryptNode_Result_File  )
		die(usage);

	if( !plaintext_file )
	{
		if(  strlen(aes_plaintext_file) > 4 && 
				!strcmp(aes_plaintext_file + strlen(aes_plaintext_file) - 4, ".aes") )
			plaintext_file = g_strndup(aes_plaintext_file, strlen(aes_plaintext_file) - 4);
		else
			plaintext_file = strdup(aes_plaintext_file);
	}
	
	if( keep && !strcmp(DO_Cph_file, plaintext_file) )
		die("Input DO ciphertext file and Plaintext file have the same designation: (try -o)\n");

	if( !strcmp(aes_plaintext_file, plaintext_file) )
		die("Input AES version of Plaintext file and Plaintext file have the same designation: (try -o)\n");
}


int main( int argc, char** argv )
{

	/* we start the timer */
	start = clock();

	bswabe_pub_t* pub; /* Public key pointer */
	arsanvkabe_prv_user_t* user_key; /* pointer on data user complete secret key */
	GByteArray* cph_do_buf; /* To hold the Aes decrypted and serialized content of DO ciphertext */
	arsanvkabe_cph_DO_t* cph_do; /* reconstructed DO second stage ciphertext */
	arsanvkabe_cph_RRD_t* cph_rrd; /* ciphertext from cloud server */

	// decryption proof elements
	element_t proof_T;
	element_t proof_I;

	/* RRD decryption parameter*/
	element_t decrypt_proof;
	

	parse_args(argc, argv);
	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

	
	/* Unserializing the complete user secret key */
	GByteArray* user_key_GByteArray=0;
	user_key_GByteArray = g_byte_array_new();
	user_key_GByteArray = load_gbyte_array(user_key_file);
	user_key = arsanvkabe_prv_user_unserialize(pub, user_key_GByteArray, 1); 
	

	/* Unserializing the RRD decryption result*/
	GByteArray* decryption_Result_GByteArray=0;
	decryption_Result_GByteArray = g_byte_array_new();
	decryption_Result_GByteArray = load_gbyte_array(decryptNode_Result_File);
	element_init_GT(proof_T, pub->p);
	element_init_GT(proof_I, pub->p);
	int offset_RRD_decrypt=0;
	unserialize_element(decryption_Result_GByteArray, &offset_RRD_decrypt, proof_T); //can be used to remove e(g,g)^{alpha.s1}
	unserialize_element(decryption_Result_GByteArray, &offset_RRD_decrypt, proof_I);


	/* Unserializing the DO ciphertext */
	cph_do_buf = g_byte_array_new();
	cph_do_buf = load_gbyte_array(DO_Cph_file);
	cph_do =  arsanvkabe_cph_DO_unserialize( pub, cph_do_buf, 1 ); /* freeing cph_do_buf */


	/*----------------------------------------*/
	/* witness recomputation and verification */
	/*----------------------------------------*/
	
	// must use the proof_T then see how it goes

	/* Data user conducts the following private computation */
	element_t decrypt_param1;
	element_init_GT(decrypt_param1, pub->p);
	element_pairing(decrypt_param1, cph_do->c, user_key->D->d); //e(g,g)^alpha.s2 . e(g,g)^r.s2

	element_t decrypt_param2;
	element_init_GT(decrypt_param2, pub->p);
	element_div(decrypt_param2, decrypt_param1, proof_I); //e(g,g)^alpha.s2 . e(g,g)^r.s2 / e(g,g)^r.s2
	
	
	// ephemeral variables
	element_t witness_term;
	element_init_GT(witness_term, pub->p);
	element_mul(witness_term, cph_do->cs, decrypt_param2); /* M.e(g, gp)^{alpha.s2} . e(g, gp)^{alpha.s2} */
	
	char* str_from_pairing = 0;
 	str_from_pairing = pairing_to_string(witness_term); /* GT -> {0,1}^{L} */

	element_t dodis_yamplolskiy_exp;
	element_init_Zr(dodis_yamplolskiy_exp, pub->p);
	element_from_string(dodis_yamplolskiy_exp, str_from_pairing);
	element_invert(dodis_yamplolskiy_exp, dodis_yamplolskiy_exp); 

	/* witness recomputation */
	element_t witness;
	element_init_GT(witness, pub->p);
	element_pow_zn(witness, cph_do->cs, dodis_yamplolskiy_exp);
	
	/* checking the value of the newly computed witness */
	if (element_cmp(witness, cph_do->witness) != 0 )
	{
		printf(" Invalid Witness... Decryption Aborted \n");
		die("%s", bswabe_error());
	}

	/* Valid Witness */
	
	/* Recovering the original aes seed m used to encrypt the plaintext file*/
	element_t aes_key;
	element_init_GT(aes_key, pub->p);
	element_div(aes_key, cph_do->cs, decrypt_param2);

	/* Decrypting AES encrypted content of the plaintext file */
	GByteArray* content_aes_file;
	content_aes_file = load_gbyte_array(aes_plaintext_file);
	GByteArray* original_content_byteArray;
	original_content_byteArray = aes_128_cbc_decrypt(content_aes_file, aes_key);

	
	/* serializing the decrypted content */
	store_gbyte_array(original_content_byteArray, plaintext_file); 
	
	/* in case the original fle was a plain text file, output its intelligible content */
	printf(" decrypted content for text files---> :  %s \n", suck_file_str(plaintext_file));


	/* freeing some memory */
	g_byte_array_free(content_aes_file, 1);
	g_byte_array_free(original_content_byteArray, 1);
	g_byte_array_free(decryption_Result_GByteArray, 1);
	arsanvkabe_cph_do_free(cph_do);
	element_clear(proof_T);
	element_clear(proof_I);
	element_clear(decrypt_param1);
	element_clear(decrypt_param2);
	element_clear(aes_key);
	element_clear(witness_term);
	element_clear(dodis_yamplolskiy_exp);
	element_clear(witness);

	
	if( !keep )
		unlink(DO_Cph_file);
	
	/* report ops if necessary */
/* 	if( report_ops ) */
/* 		printf("pairings:        %5d\n" */
/* 					 "exponentiations: %5d\n" */
/* 					 "multiplications: %5d\n", num_pairings, num_exps, num_muls); */


	/* Timing the experiment */
	time_diff = (clock() - start);
	
	/* clock drift report */
	printf("Time taken by cpabe-transform2 %f ms (milliseconds)\n\n",((double) (time_diff*1000) / CLOCKS_PER_SEC));
	

	return 0;
}

