/*
 * encrypt1.h
 *
 *  Created on: Nov 23, 2023
 *      Author: Arthur Sandor
 */


#include <openssl/aes.h>

#include <openssl/sha.h>

/*
 *  DO ciphertext structure
 */
struct arsanvkabe_cph_DO_s
{
	element_t cs; /* G_T */
	element_t c;  /* G_1 */
	element_t g_s2;  /* G_1 */
	element_t c_attd; /* G_2*/
	char* p; /* anonymized access policy using set homomorphism hashing */
	element_t witness; // sort of proof of ownership (like digital signature)
};

/*
 * Generation of first stage of ciphertext under DO encryption
 */
arsanvkabe_cph_DO_t* arsanvkabe_encrypt1( bswabe_pub_t* pub, element_t m, char* policy, element_t  dummy_attribute_element);
