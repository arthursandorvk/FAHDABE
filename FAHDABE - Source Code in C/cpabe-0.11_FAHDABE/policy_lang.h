/*
	Include common.h before including this file.
*/

char* parse_policy_lang( char* s );
void  parse_attribute( GSList** l, char* a );
struct bswabe_policy_t* parse_policy_postfix( char* s );


/*
 * DO structure for attribute masking factor epsilon
 */
struct arsanvkabe_epsilon_s
{
	char* epsilon_string; /* will be kept private by DO */
	char* epsilon_digest_string; /*H2(epsilon)*/ /* Will be included in DU partial key*/
};



//this structure represents our public key or the public parameters
/*
The public key is represented as PP = {g,gp, Y=e(g,gp),Ho,H1,H2,H3,P,T} U {h=g_beta, f=g_1/beta, Z=e(g,h)_alpha}

*/
struct bswabe_pub_s
{
	char* pairing_desc; //the pairing desription variable
	pairing_t p;		//the pairing_t varible will only be used as to initialize the pairings, using the pairing parameters contained in the pairing description variable pairing_desc

	element_t g;           /* G_1 */ //random element of group G_1 (can be assimilated as generator)
	element_t h;           /* G_1 */ //element of group G_1 (h=g exp beta)
	element_t gp;          /* G_2 */ //random element of group G_2 6*
	element_t g_hat_alpha; /* G_T */ // which stores the pairing e(g,h)alpha and that is why belongs to GT

	//we add the new variables for our scheme
	element_t f; /* G_2 */ 
	element_t y_no_hat; /* G_T */ //y_no_hat is the value Z=e(g,h), with no exponent.
};



// end of declaration