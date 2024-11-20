#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <pbc.h>
#include <pbc_random.h>
#include <time.h>

#include "bswabe.h"
#include "common.h"
#include "lthash_benchmark.h"


char* usage =
"Usage: cpabe-lthash_benchmark [OPTION ...]\n"
"\n"
"run a series of tests over the LTHash as well as other hash functions used. Parameters are made of the public key, and two inputs.\n"
" As inputs to the CLI, input1 and input2 can be any string value. Make sure to generate the public parameters first \n"
"\n"
"Statistics will be displayed to the screen \n"
"\n"
"Mandatory arguments to long options are mandatory for short options too.\n\n"
" -h, --help                    print this message\n\n"
" -v, --version                 print version information\n\n"
" -d, --deterministic           use deterministic \"random\" numbers\n"
"                               (only for debugging)\n\n"
"";

char* pub_file = 0; /* pub_key */


/* time difference time_diff */
clock_t time_diff=0;

/* global variables to hold the time for the beginnning and the end */
clock_t start=0;
clock_t end=0;


/* the two fixed inputs */
char* input1 = "Apple";
char* input2 = "Banana";


void
parse_args( int argc, char** argv )
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
			printf(CPABE_VERSION, "-lthash_Benchmark");
			exit(0);
		}
		
		else if( !strcmp(argv[i], "-d") || !strcmp(argv[i], "--deterministic") )
		{
			pbc_random_set_deterministic(0);
		}
		else if( !pub_file )
		{
			pub_file = argv[i];
		}
		/* Uncomment to provide your own inputs */

		/*else if( !input1 )
		{
			input1 = argv[i]; //first input
		}
		else if( !input2 )
		{
			input2 = argv[i]; //second input
		}*/

		else
			//die(usage);

	if( !pub_file ) // || !input1 || !input2)
	{
		die(usage);
		g_error("An error Occured! Provide the name of the file containing the public key \n");
	}
}


int
main( int argc, char** argv )
{
	bswabe_pub_t* pub;
	
	parse_args(argc, argv);
	
	pub = bswabe_pub_unserialize(load_gbyte_array(pub_file), 1);


	GByteArray *content_do_epsilon;
	content_do_epsilon = g_byte_array_new();
	content_do_epsilon = load_gbyte_array(EPSILON_FILE);
	
	/* unserializing the value of epsilon */
	arsanvkabe_epsilon_t* DO_epsilon=0;
	DO_epsilon = arsanvkabe_do_epsilon_unserialize(pub, content_do_epsilon, 1);
	
	/* Benchmarking H0() */
	/* computing digest using the  first input (input1)*/
	start = clock();
	element_t input1_H0;
	element_init_Zr(input1_H0, pub->p);
	element_from_string(input1_H0, input1);
	end = clock();
	time_diff = (end - start);
	/* clock drift report */
	printf("Time taken to compute H0(%s) %f ms (milliseconds)\n\n", input1, ((double)(time_diff) / CLOCKS_PER_SEC));
	
	/* Benchmarking H1() */
	/* computing digest using the  first input (input1)*/
	start = clock();
	element_t input1_H1;
	element_init_G2(input1_H1, pub->p);
	element_from_string(input1_H1, input1);
	end = clock();
	time_diff = (end - start);
	/* clock drift report */
	printf("Time taken to compute H1(%s) %f ms (milliseconds)\n\n", input1, ((double)(time_diff) / CLOCKS_PER_SEC));
	
	
	/* Benchmarking H2() */
	/* computing digest using the  first input (input1)*/
	start = clock();
	char* input1_H2 = compute_Lthash_return_string(input1);
	end = clock();
	time_diff = (end - start);
	/* clock drift report */
	printf("Time taken to compute H2(%s) %f ms (milliseconds)\n\n", input1, ((double)(time_diff) / CLOCKS_PER_SEC));
	
	
	/* Benchmarking H3() */
	/* computing digest using the first input (input1)*/
	start = clock();
	element_t input1_H3;
	element_init_G1(input1_H3, pub->p);
	element_from_string(input1_H3, input1);
	end = clock();
	time_diff = (end - start);
	/* clock drift report */
	printf("Time taken to compute H3(%s) %f ms (milliseconds)\n\n", input1, ((double)(time_diff) / CLOCKS_PER_SEC));
	
	

	/* Benchmarking H2(input1 + input2) */
	/* computing digest using the first input (input1)*/
	start = clock();
	char* input1_H4 = compute_Lthash_Add_inputs_return_string(input1, input2);
	end = clock();
	time_diff = (end - start);
	/* clock drift report */
	printf("Time taken to compute H2(%s + %s) %f ms (milliseconds)\n\n", input1, input2, ((double)(time_diff) / CLOCKS_PER_SEC));
	



	/* Benchmarking H2(input1) + H2(input2) */
	/* computing digests using the first input (input1) and the value input2 */
	char* input1_array = compute_Lthash_return_string(input1);

	/* Need a buffer file for python and C communication */
	char path_to_file[] = "/home/summer/temp_skyfall.txt";
	/* Writing the H2(input1) expression into the file */
	FILE *fp_input1 = fopen(path_to_file, "w");
	if (fp_input1 == NULL)
	{
		printf("cannot open the file %s", path_to_file);
		fprintf(stderr, "fopen() failed for '%s'\n", path_to_file);
		return 1;
	}
	else
	{
		char input1_array_str[200];
		strcpy(input1_array_str, input1_array);
		for (int i=0; i < strlen(input1_array_str); i++)
		{
			fputc(input1_array_str[i], fp_input1);
		}
		fclose(fp_input1);
	}

	/* H2(input1) + (input2) */
	start = clock();
	char* result_hash_add_data = compute_Lthash_Digest_hidden_epsilon(input2);
	end = clock();
	time_diff = (end - start);
	/* clock drift report */
	printf("Time taken to compute H2(%s) + H2(%s) %f ms (milliseconds) \n\n", input1, input2, ((double)(time_diff*1000) / CLOCKS_PER_SEC));
	

	return 0;
}
