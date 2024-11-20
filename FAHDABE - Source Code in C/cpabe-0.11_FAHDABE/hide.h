/*
 * hide.h
 *
 *  Created on: Apr 19, 2023
 *      Author: Arthur Sandor
 */


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

/*
 *To allow Data users to hide their attributes prior to requesting attribute keys from AAs
 */
char** arsanvkabe_hide(bswabe_pub_t* pub, char** attributes);
