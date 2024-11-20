#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>

#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"

#include "encrypt2.h"
#include <assert.h>



char* usage =
"Usage: cpabe-encrypt2 [OPTION ...] PUB_KEY CT_DO_FILE \n"
"\n"
"Enforce the hidden access policy formulated by DO in CT_DO_FILE using the public key\n"
"PUB_KEY. The encrypted file will be written as CT_DO_FILE.cpabe unless\n"
"the -o option is used. The original CT_DO_FILE file will be removed unless\n"
" the k oprion is used.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -k, --keep-input-file    don't delete original file\n\n"
" -o, --output FILE        write resulting ciphertext to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

char* pub_file = 0; /* File containing the public key */
char* ct_do_in_file  = 0; /* File containing the first stage ciphertext from DO */
char* out_file = 0; /* Output ciphertext file name computed by the resource-rich device (RRD)*/
int   keep     = 0; /*boolean: whether to keep the ct_do ciphertext */

char* policy = 0; /* parsed and hidden access policy */

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
			printf(CPABE_VERSION, "-encryptCT_RRD");
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
		else if( !ct_do_in_file )
		{
			ct_do_in_file = argv[i];
		}
		else
			die(usage);

	if( !pub_file || !ct_do_in_file )
		die(usage);

	if( !out_file )
		out_file = g_strdup_printf("%s.cpabe", ct_do_in_file);
}

int
main( int argc, char** argv )
{
	/* Initialization */
	bswabe_pub_t* pub;

	arsanvkabe_cph_RRD_t* cph_rrd; /* second stage ciphertext to be returned */

	arsanvkabe_cph_DO_t* cph_DO;
	
	int file_len;
	
	GByteArray* ct_DO_GbyteArray;
	
	GByteArray* cph_rrd_buf;
	
	GByteArray* aes_ct_do_buf;
	
	GByteArray* plt_ct_do;
	
	element_t m; /* content from CT_DO_FILE will be encrypted using a novel aes key seeded with m */
	

	parse_args(argc, argv);

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

	/* unserializing DO ciphertext */
	GByteArray *CT_DO_ByteArray=0;
	CT_DO_ByteArray = g_byte_array_new();

	CT_DO_ByteArray = load_gbyte_array(ct_do_in_file); /* DO ciphertext content used for processing */
	plt_ct_do = load_gbyte_array(ct_do_in_file); /* DO ciphertext content waiting to be encrypted with AES */

	cph_DO = arsanvkabe_cph_DO_unserialize(pub, CT_DO_ByteArray, 1); /* freeing the CT_DO_ByteArray */


	/* computing RRD ciphertext */
	cph_rrd = arsanvkabe_encrypt2( pub, m, cph_DO );
  	if( (cph_rrd == NULL) ) 
		die("%s", bswabe_error());


	/* serializing the RRD ciphertext */
	cph_rrd_buf = arsanvkabe_cph_RRD_serialize( cph_rrd );

	/* encrypting the original DO ciphertext content in plt_ct_do with AES */
	file_len = plt_ct_do->len;
	aes_ct_do_buf = aes_128_cbc_encrypt(plt_ct_do, m); /* the AES key seed */

	/* Writing out the RRD ciphertext */
	write_cpabe_file(out_file, cph_rrd_buf, file_len, aes_ct_do_buf);

	/* freeing some memory */
	g_byte_array_free(cph_rrd_buf, 1);
	g_byte_array_free(aes_ct_do_buf, 1);
	g_byte_array_free(plt_ct_do, 1);

	arsanvkabe_cph_do_free(cph_DO);
	arsanvkabe_cph_rrd_free(cph_rrd);
	element_clear(m); /* this secret m at the level of RRD */
	

	/* Whether to remove the DO ciphertext */
	if( !keep )
		unlink(ct_do_in_file); 

	
	/* Timing the experiment */
	time_diff = (clock() - start);
	
	/* clock drift report */
	printf("Time taken by cpabe-encrypt2 %f ms (milliseconds)\n\n",((double) (time_diff*1000) / CLOCKS_PER_SEC));
		
	
	
	return 0;
}
