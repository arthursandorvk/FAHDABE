/*
 * hide.c
 *
 *  Created on: Apr 17, 2024
 *      Author: Arthur Sandor
 */
/*
 * This Source file defines the Data User Process of Hiding the values of its attributes
 * while keeping the name of attributes public: This source file enforces partially policy
 * hiding in multi-authority CP-ABE.
 * to do so, DU needs the masking attribute factor sent by the DO as a string so that the DU
 * could combine each of its attribute and the attribute masking factor using homomorphic hashing.
 * The process is conducted locally by the user. The process is flexible since a user with higher 
 * privacy valuation will choose to hide its attribute values. Since the DO hides the values of attributes
 * in the access policy, it is somewhat mandatory to hide attributes so as to be able to decrypt
 */

//the include section
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
#include "hide.h"

//end of the include section

char* usage =
"Usage: cpabe-hide [OPTION ...] PUB_KEY DO_KEY_FILE ATTRS \n"
"\n"
"Hide the set of users attribute values ATTRS using public key PUB_KEY and DO_key in DO_KEY_FILE.\n" 
"This scheme considers that users obtain their attributes in advance."
"Output will be written to the default file \"Hidden_Attr_File\" unless the -o option is specified.\n"
"\n"
"\n"
"In this work, public attribute schemas for each Attribute authority as well as User profiles containing attribute names (as tuples) are publicly available."
"Each attribute can be represented by a simple string value and numbers will be treated as characters: it supports non-Numerical attribute values."
"Each user only needs to specify the value of each attribute w.r.t its profile. "
"The system will hide such attributes; the system upholds attribute hiding."
"\n"
"The keywords `and', `or', and `of', are reserved for the policy language\n"
"of cpabe-enc (1) and may not be used for either type of attribute.\n"
"\n"

"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";
//end of Usage

/* Global variables */

/* File containing the public parameters */
char*  pub_file = 0; 

/*Output File*/
char*  out_file = DEFAULT_HIDDEN_ATTR_FILE;

/* File containing the partial key issued by DO */
char* do_key_file = 0;

/*Array of Attributes*/
char** attrs;

/* Secret key component issued by DO */
arsanvkabe_prv_do_t* DO_key=0;


/* variables to hold the start and end time */
clock_t start=0;
clock_t end=0;

/* time difference time_diff */
clock_t time_diff=0;
	


gint comp_string( gconstpointer a, gconstpointer b)
{
	return strcmp(a, b);
}


void
parse_args( int argc, char** argv )
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
			printf(CPABE_VERSION, "-hideDU_ATTR");
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
        	else if( !do_key_file )
       		{
            		do_key_file = argv[i];
        	}
		else
		{
		   arsanvkabe_parse_attribute(&alist, argv[i]);
		}

	if( !pub_file || !alist || !do_key_file)
	{
		printf("**** Some parameters are missing !!! \n");		
		die(usage);
	}

    alist = g_slist_sort(alist, comp_string);
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

   bswabe_pub_t* pub=0;

    parse_args(argc, argv);

    printf("unserializing the public key \n");

    pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

	
    printf("Unserializing the DO key \n");

    DO_key = arsanvkabe_prv_do_unserialize(pub, load_gbyte_array(do_key_file),1);

	
	/* Write the value of DO_key->epsilon_digest_string  in file to help Python and C compute 
	the hidden value of each attribute */

	FILE *fp_input_lthash = fopen(TEMPORAL_RESULTS_FILE_NAME, "w");
	
	if (fp_input_lthash == NULL)
	{
		die("cannot open the file %s", TEMPORAL_RESULTS_FILE_NAME);
	}
	else
	{
		for (int i=0; i < strlen(DO_key->epsilon_digest_string); i++)
		{
			fputc(DO_key->epsilon_digest_string[i], fp_input_lthash);
		}

		fclose(fp_input_lthash);
	}

    /* to hide attribute values provided */
    attrs = arsanvkabe_hide(pub, attrs);


    /* To store hidden attributes in file */
    FILE* hidden_attr_file = fopen(out_file, "w");
    
    if (hidden_attr_file == NULL)
    {
        die("Cannot open file %s \n", out_file);
    }

	/* Write down the hidden version of each attribute */
    for (gsize i=0; attrs[i] != NULL; i++)
    {
		/* Remove a possible trailing newline in each individual attribute */
		/* perhaps a bit of repetition as in arsanvkabe_hide_attribute() */
		attrs[i] = g_strstrip(attrs[i]);

		/* write the actual line down the file */
        int bytes_written = fputs(attrs[i], hidden_attr_file);

		/* Check whether any EOF is reached */
        if (bytes_written == EOF)
        {
            fclose(hidden_attr_file);
             die("EOF error when writing in %s \n", out_file);
        }

        /* add newline delimiter between strings (after each attribute in the file) */
        fputc('\n', hidden_attr_file);
		
    }

    fclose(hidden_attr_file);

	/* Timing the experiment */
	time_diff = (clock() - start);
	
	/* clock drift report */
	printf("Time taken by cpabe-hideDU_Attr %f ms (milliseconds)\n\n",((double) (time_diff*1000) / CLOCKS_PER_SEC));
	

	return 0;
}
