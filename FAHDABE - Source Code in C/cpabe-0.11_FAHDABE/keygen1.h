/*
 * keygen1.h
 *
 *  Created on: Dec 04, 2023
 *      Author: Arthur Sandor
 */

# include "bswabe.h"
/*
 *  Generate the private key D with the public key, the master key, the dummy attribute and the attribute masking factor epsilon 
 */
//arsanvkabe_prv_do_t* arsanvkabe_keygenDO( bswabe_pub_t* pub, bswabe_msk_t* msk, char** dummy_attributes, arsanvkabe_epsilon_t* do_epsilon );
arsanvkabe_prv_do_t* arsanvkabe_keygen1( bswabe_pub_t* pub, bswabe_msk_t* msk, char* user_gid, char** dummy_attributes, arsanvkabe_epsilon_t* do_epsilon);

/* 
 * Data Owner Secret Key Component 
 */
struct arsanvkabe_prv_do_s
{
	element_t d;   /*G_2*/ 
	element_t du_blind; /*G_2*/
	element_t hkey; //helper key g^{\gamma / \beta}
	char* epsilon_digest_string; /* H2(epsilon) */ 
	GArray* dummy_attr_array; /* arsanvkabe_prv_comp_t's */ //Array of dummy attributes (only one in this work)
};
