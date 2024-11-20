/*
 * keygen1.c
 *
 *  Created on: Nov 30, 2023
 *      Author: Arthur Sandor
 */
/*
 * This Source file defines the Data Owner process of producing
 * the partial key component for Data User 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>


#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"

#include "keygen1.h"



char* usage =
"Usage: cpabe-keygen1 [OPTION ...] PUB_KEY MASTER_KEY USER_GID DUMMY_ATTR  \n"
"\n"
"Generate the data owner key with using public key PUB_KEY, \n"
"master secret key MASTER_KEY, the USER GID in USER_GID, and the dummy attribute DUMMY_ATTR (in Non Numerical Form)\n" 
"or a list of dummy attributes for future work. Output will be written to the file \"DO_key\" \n"
"unless the -o option is specified.\n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";


char*  pub_file = 0; /* file hosting public key */

char*  msk_file = 0; /* fle hosting master key */

char*  out_file = DO_KEY_FILE; /* output file */

char* du_blind_file = DU_BLIND_PARAM_FILE_NAME; /* file pointer to the du_blind parameter sent by DO to the DU */

char* user_gid = 0; /* value of the user GID */

/* Array containing the dummy attribute. 
This work enables the definition of multiple dummy attributes but only considers the first 
dummy attribute in the list (it uses a single dummy attribute). */
char** attrs; 


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
	GSList* alist;

	alist = 0;

	for( i = 1; i < argc; i++ )
		if( !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(CPABE_VERSION, "-keygenDO");
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
		else if( !msk_file )
		{
			msk_file = argv[i];
		}
		else if( !user_gid)
		{
			user_gid = argv[i];
		}
		else
		{
			/* To enforce non numerical attributes for the dummy attribute */
			arsanvkabe_parse_attribute(&alist, argv[i]);
		}

	/* Input requirements*/
	if( !pub_file || !msk_file || !user_gid ||  !alist )
		die(usage);


	int n;
	GSList* ap;
	alist = g_slist_sort(alist, comp_string); /* processing input dummy attribute(s) */
	n = g_slist_length(alist);

	attrs = malloc((n + 1) * sizeof(char*));

	i = 0;
	for( ap = alist; ap; ap = ap->next )
		attrs[i++] = ap->data;
	attrs[i] = 0;
}


int main(int argc, char **argv)
{
	/* We start the timer */
	start = clock();

	parse_args(argc, argv);
	
	bswabe_pub_t* pub = 0; /* public key pointer */
	bswabe_msk_t* msk = 0; /* master key pointer */
	arsanvkabe_prv_do_t* prv = 0; /* secret key component for Data User (DU) */
	arsanvkabe_epsilon_t* do_epsilon = 0; /* DO structure for attribute masking factor epsilon */


	pub = bswabe_pub_unserialize(suck_file(pub_file), 1); 
	msk = bswabe_msk_unserialize(pub, suck_file(msk_file), 1);
	

	/* Loading epsilon structure on the DO side */
	GByteArray *content_do_epsilon;
	content_do_epsilon = g_byte_array_new();
	content_do_epsilon = load_gbyte_array(EPSILON_FILE);


	/* Unserializing DO epsilon structure*/
	int offset_epsilon=0;
	do_epsilon = arsanvkabe_do_epsilon_unserialize( pub, content_do_epsilon, 1 );
	


	/* Generating DO key component for DU*/
	prv = arsanvkabe_keygen1(pub, msk, user_gid, attrs, do_epsilon);
	

	/* Serializing DU_blind */
	GByteArray *du_blind_byte_array=0;
	du_blind_byte_array = g_byte_array_new();
	//
	serialize_element(du_blind_byte_array, prv->du_blind);
	store_gbyte_array(du_blind_byte_array, du_blind_file);

	/* freeing memory */
	g_byte_array_free(du_blind_byte_array, 1);


	/* Serializing the DO key */
	GByteArray *DO_key_byte_array=0;
	DO_key_byte_array = g_byte_array_new();

	DO_key_byte_array = arsanvkabe_prv_do_serialize(prv);
	store_gbyte_array(DO_key_byte_array, out_file);


	/* freeing memory */
	g_byte_array_free(DO_key_byte_array, 1);

	arsanvkabe_prv_do_t_free(prv);

	/* Timing Experiments */
	time_diff = (clock() - start);
	
	/* clock drift report */
	printf("Time taken by cpabe-keygen1 %f ms (milliseconds)\n\n",((double) (time_diff*1000) / CLOCKS_PER_SEC));
	
	return 0;
}


