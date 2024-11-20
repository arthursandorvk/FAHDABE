/*
 * keygenRRD.c
 *
 *  Created on: Nov 28, 2023
 *      Author: Arthur Sandor
 */

/*
 * This program enables any resource rich Device (RRD) of the user's choice to execute heavy computations on behalf of 
 * such user. RRD performs two main operations: 
 * (1) Updating the attribute component c.d in every AAkey 
 * (2) Putting all the updated AAkeys in a unique structure called the RRD key that will serve as to outsource decryption		
 */

//Include section
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
#include "keygen3.h"


char* usage=
"Usage: cpabe-keygen3 [OPTION ...] PUB_KEY DU_BLIND_FILE AA_key1 [AA_key2 ...]\n"
"\n"
"Generate a RRD (resource-rich device) key with the listed AA secret\n"
"key files obtained from different attribute authorities.\n" 
"cpabe-keygen3 uses the public key PUB_KEY, the DO issued parameter in file \n" 
"DU_BLIND_FILE to apply shared randomness on AA key components, and the various files\n" 
"containing AA keys such as AA_key1... Output will be written to the file\n"
"\"rrd_key\" unless the -o option is specified.\n"
"\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";




char *pub_file = 0; /* file containing th public key */

char *AA_file = 0; /* file pointer on an Attribute Authority Secret key */

char* du_blind_file = 0; /* file pointer to the du_blind parameter sent by DO to the DU */

char* out_file = RRD_KEY_FILE; /* Output file for the rrd_key */

bswabe_pub_t *pub = 0; 

GArray *fileAAlist=0; /* Contains Attribute Authority secret key files passed as command line arguments */


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
	
	fileAAlist = g_array_new(0, 1, sizeof(char*));
	
	for( i = 1; i < argc; i++ )
		if(     !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(CPABE_VERSION, "-keygenRRD");
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
		else if( !du_blind_file )
		{
			du_blind_file = argv[i];
		}
        else
		{
		  g_array_append_val(fileAAlist, argv[i]); /* Add AA secret key filenames to the GArray* fileAAlist */
		}

	if(  !pub_file || !du_blind_file || !fileAAlist )
		die(usage);
}


int main(int argc, char **argv)
{
	/* We start the timer */
	start = clock();

	arsanvkabe_RRD_key_t* rrdKey = 0; //the resource-rich device key 

	parse_args( argc, argv );

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

	/* Unserializing the DO_key->du_blind */
	GByteArray* b_du_blind;
	b_du_blind = g_byte_array_new();
	b_du_blind = load_gbyte_array(du_blind_file);

	element_t du_blind;
	element_init_G1(du_blind, pub->p);
	int offset;
	offset = 0;
	unserialize_element(b_du_blind, &offset, du_blind);

	/* Main processing */
	rrdKey = arsanvkabe_keygen3(pub, fileAAlist, du_blind);

	/* Serializing the rrdKey */
	GByteArray* b=0;
	b = g_byte_array_new();
	b = arsanvkabe_prv_rrdKey_serialize(rrdKey);
	store_gbyte_array(b, out_file);
	

	/* freeing some memory*/
	g_byte_array_free(b, 1);
	g_byte_array_free(b_du_blind, 1);

	arsanvkabe_RRD_key_t_free(rrdKey);

	element_clear(du_blind);


	/* Timing Experiments */
	time_diff = (clock() - start);
	
	/* clock drift report */
	printf("Time taken by cpabe-keygen3 %f ms (milliseconds)\n\n",((double) (time_diff*1000) / CLOCKS_PER_SEC));
	

	return 0;
}
