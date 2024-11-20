/*
 * lthash_benchmark.h
 *
 *  Created on: Nov 23, 2023
 *      Author: Arthur Sandor
 */

#include <glib.h>
#include <sys/mman.h>
#include <sys/stat.h>        /* For mode constants */
#include <fcntl.h>   


// we define configuration parameters for LTHash
#define STATE_WORDS 8


/*
Include glib.h, pbc.h, and bswabe.h before including this file.
*/


/*
 *public parameters PP
 */
struct bswabe_pub_s
{
	char* pairing_desc; 
	pairing_t p;
	element_t g;           /* G_1 */ 
	element_t h;           /* G_1 */
	element_t gp;          /* G_2 */
	element_t g_hat_alpha; /* G_T */
	element_t f; /* G_2 */ 
	element_t y_no_hat; /* G_T */ 
	
};