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

#include "keygen0.h"


char* usage =
"Usage: cpabe-keygen0 [OPTION ...] PUB_KEY ATTR_MASKING_VALUE\n"
"\n"
"cpabe-keygen0 leverages the public key PUB_KEY and the description of the parameter epsilon\n" 
"EPSILON_MASKING_VALUE to mask the attribute value. Output will be written to the file epsilon_homomorphic_param\n" 
"unless the -o option is specified.\n"
"\n"
"cpabe-keygen0 generates the attribute masking factor epsilon to realize partially hidden access policy\n" 
"evaluation. The factor epsilon helps to conceal the value of attributes in the access policy, DO computes the\n" 
"digest H2(epsilon) and sends it to DU. the value of the dummy attribute is hidden with epsilon.\n" 
"Given attribute value attr, DU computes H2(epsilon) + H2(attr) to achieve H2(epsilon + attr).\n" 

"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help               print this message\n\n"
" -v, --version            print version information\n\n"
" -o, --output FILE        write resulting key to FILE\n\n"
" -d, --deterministic      use deterministic \"random\" numbers\n"
"                          (only for debugging)\n\n"
"";

/*
	TODO ensure we don't give out the same attribute more than once (esp
	as different numerical values)
*/

char*  pub_file = 0; /* public key file*/

char* epsilon_string_value = 0; /* plain attribute maskin factor epsilon */ 

char*  out_file = EPSILON_FILE; 


/* Global variables to hold the start and end time */
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
	{
		if(      !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help") )
		{
			printf("%s", usage);
			exit(0);
		}
		else if( !strcmp(argv[i], "-v") || !strcmp(argv[i], "--version") )
		{
			printf(CPABE_VERSION, "-keygenEpsilon");
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
		else if( !epsilon_string_value )
		{
			epsilon_string_value = argv[i];
		}
		else
		{
			// do nothing
			;			
		}
	} // end of for loop

	if( !pub_file || !epsilon_string_value )
		die(usage);
}

int main( int argc, char** argv )
{
	/* we start the timer */
	start = clock();

	/* public parameters */ 	
	bswabe_pub_t* pub;

	/* structure to store epsilon details on DO side*/
	arsanvkabe_epsilon_t* DO_epsilon;


	parse_args(argc, argv);

	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);

	/* Generating epsilon structure on DO side */
	DO_epsilon = arsanvkabe_keygen0(pub, epsilon_string_value);


	/* serializing epsilon structure for DO. THis is necessary for policy hiding */
	GByteArray* b_epsilon;
	b_epsilon = g_byte_array_new();
	b_epsilon = arsanvkabe_do_epsilon_serialize(DO_epsilon);
	store_gbyte_array( b_epsilon, out_file);

	
	/* freeing other variables */
	g_byte_array_free(b_epsilon, 1);


	/* Timing the experiment */
	time_diff = (clock() - start);
	
	/* clock drift report */
	printf("Time taken by cpabe-keygen0 %f ms (milliseconds)\n\n",((double) (time_diff*1000) / CLOCKS_PER_SEC));
	

	return 0;
}
