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

char* usage =
"Usage: cpabe-benchmark public_key_file\n"
"\n"
"Generate the cost of multiplications, exponentiations and pairings in G1, G2 and GT\n"
"\n"
" this function takes as Mandatory arguments the sytem public key.\n\n"
"";

char* pub_file = 0;
//
/* Global variables to hold the start and end time */
clock_t start = 0;
clock_t end = 0;

/* time difference time_diff */
clock_t time_diff = 0;

void
parse_args( int argc, char** argv )
{
	int i;

	for( i = 1; i < argc; i++ )
		if( !pub_file )
		{
			pub_file = argv[i];
		}
		else
			die(usage);

	if( !pub_file )
		die(usage);	

}

//

int
main( int argc, char** argv )
{
	/* We start the timer */
	start = clock();

	parse_args(argc, argv);

	bswabe_pub_t* pub; /* public key */
	pub = bswabe_pub_unserialize(suck_file(pub_file), 1);
	
	pbc_benchmark(pub);

	end = clock();

	time_diff = (clock() - start);
	
	/* clock drift report */
	printf("Time taken by cpabe-benchmark %f ms (milliseconds)\n\n",((double) (time_diff*1000) / CLOCKS_PER_SEC));
	
	
return 0;
}




