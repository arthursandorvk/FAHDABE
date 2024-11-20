/*
 * keygen2.c
 *
 *  Created on: Nov 28, 2023
 *      Author: Arthur Sandor
 */

/*
 * This Source file defines the Attribute Authority Process to produce secret key components for attributes
 * it manages. Those components include the components d and d' for each attribute in the previous CP ABE (BSW-CP-ABE).
 * THis work assumes the data user communicates with the Resource Rich Device ( such as a cloud server)
 * to outsource heavy computation such as Partial Decryption or future revocation operations.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/stat.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include "bswabe.h"
#include "common.h"
#include "policy_lang.h"
#include "keygen2.h"

#define MAX_LINE_LEN 256 /* Max size of buffer to read a line in text file of hidden attributes */


char* usage =
"Usage: cpabe-keygen2 [OPTION ...] PUB_KEY FILE_WITH_USER_HIDDEN_ATTRIBUTES USER_GID \n"
"\n"
"Generate the attribute authority key component using the system public key PUB_KEY, \n"
"a set of hidden attributes present in a file FILE_WITH_USER_HIDDEN_ATTRIBUTES, \n"
"and the user global identifier expressend as string value USER_GID\n"
"Attributes names are known in advance and each AA manages a set of attributes.\n"
"Output will be written to the file \"AA_key\" unless the -o option is specified.\n" 
"Additional command line arguments will be ignored. \n"
"\n"
"\n"
"In this work, attributes come in non-numerical form . Non-numerical\n"
"attributes are simply any string of letters, digits, and underscores\n"
"beginning with a letter or a digit or any other character. If your attribute\n" 
"starts with a special character such as *&^%^-_arthurMartins, you need to quote\n"
"your attribute( \"*&^%^-_arthurMartins\") to avoid confusing the system interpreter.\n" 
"\n"
"\n"
"Numerical attributes are not yet supported. They are specified as `attr = N', where N is a non-negative\n"
"integer less than 2^64 and `attr' is another string. The whitespace around\n"
"the `=' is optional. One may specify an explicit length of k bits for the\n"
"integer by giving `attr = N#k'. Note that any comparisons in a policy given\n"
"to cpabe-enc(1) must then specify the same number of bits, e.g.,\n"
"`attr > 5#12'.\n"
"\n"
"The keywords `and', `or', and `of', are reserved for the policy language\n"
"and may not be used for either type of attribute.\n"
"\n"

"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n";



char*  pub_file = 0; /* public key file */

char*  out_file = AA_KEY_FILE; /* Default file to output AAkey */

char*  in_file = 0; /* File containing the hidden attributes as char** */

char** attrs; /* Array to contain hidden attributes */

char* user_gid = 0; /* the user global identifier*/


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
	GSList* ap;
	int n;

	alist = 0;
	for( i = 1; i < argc; i++ )
		if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(CPABE_VERSION, "-keygenAA");
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
		else if( !in_file )
		{
			in_file = argv[i];
		}
		else if( !user_gid )
		{
			user_gid = argv[i];
		}
		else
		{
			; /* If more than three aguments, raise error */
			die(usage);
		}

	if( !pub_file || !in_file || !user_gid )
		die(usage);

	/* Read Hidden Attributes from file */
	FILE* hidden_attr_file = fopen(in_file, "r");

	if (hidden_attr_file == NULL)
	{
		die("Cannot Open file %s to get user hidden attributes \n", in_file);
	}
	else
	{
		; //do nothing
	} 
	/* No error on the file */

	/* Read each line from file as a single attribute */
	char* line_to_read = 0;
	line_to_read = (char*)malloc(MAX_LINE_LEN * sizeof(char));

	while (fgets(line_to_read, MAX_LINE_LEN, hidden_attr_file) != NULL)
	{
		/* Remove a possible leading or trailing newline or space */
		line_to_read = g_strstrip(line_to_read);
	
		char* hidden_attr = strdup(line_to_read); /* Allocate memory for the extracted line (copy line into a new variable) */
		
		/* Process the extracted hidden attribute */
		arsanvkabe_parse_attribute( &alist, hidden_attr );
		
	} //end while loop

	/* close the file */
	fclose(hidden_attr_file);


	/* Process the GSLIST *alist */
    alist = g_slist_sort(alist, comp_string);
	n = g_slist_length(alist);

	attrs = malloc((n + 1) * sizeof(char*));

	i = 0;
	for( ap = alist; ap; ap = ap->next )
		attrs[i++] = ap->data;
	attrs[i] = 0;

} //end of parse_args


int main(int argc, char **argv)
{	
    bswabe_pub_t* pub=0; /* public parameters */

    skAA_t* prv=0; /* Attribute Authority secret Key structure */

    parse_args(argc, argv); /* Parsing command line arguments */

    pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

    prv = arsanvkabe_keygen2(pub, attrs, user_gid);


    GByteArray* AA_key_byte_array;
    AA_key_byte_array = g_byte_array_new();
    AA_key_byte_array =  arsanvkabe_prv_AA_serialize(prv);
    

    store_gbyte_array( AA_key_byte_array, out_file); /* Storing the new AA key */

    // freeing resources
    g_byte_array_free(AA_key_byte_array, 1);
    bswabe_pub_free(pub);
    skAA_t_free(prv);

    /* Timing the experiment */
    time_diff = (clock() - start);
	
    /* clock drift report */
    printf("Time taken by cpabe-keygen2 %f ms (milliseconds)\n\n",((double) (time_diff*1000) / CLOCKS_PER_SEC));
	

    return 0;
}
