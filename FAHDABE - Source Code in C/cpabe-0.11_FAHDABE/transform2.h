/*
 * transform2.h
 *
 *  Created on: Nov 19, 2024
 *      Author: Arthur Sandor
 */


/*
 * first stage ciphertext from encryption by DO
 */
struct arsanvkabe_cph_DO_s
{
	element_t cs; /* G_T */ // M=e(g,g)alpha*s_{2}
	element_t c;  /* G_1 */ // C= g^{beta *s_{2}} = h^{s_{2}}
	element_t g_s2;  /* G_1 */ //g_s2 = g^{s_{2}}
	element_t c_attd; /* G_2*/ // c_attd = H1(H2(j+epsilon))^{s2} = g2^{H2(j+epsilon) * {s2}}
	char* p; /* anonymized access policy using set homomorphism hashing */
	element_t witness; // sort of proof of ownership (like digital signature)
};


/*
 *RRD key made of a GByteArray of AAKeys
 */
struct arsanvkabe_RRD_key_s
{
	GArray* AAkey_array;
};


/*
 * Complete user secret key
 */
struct arsanvkabe_prv_user_s
{
	arsanvkabe_prv_do_t* D; /* partial key issued by DO*/
	arsanvkabe_RRD_key_t* U; /* bswabe_prv_comp_t's */
};

/*
 * User public subkey DO_Out_key sent to RRD for policy evaluation and partial decryption
 */
struct arsanvkabe_user_rrd_subkey_s
{
	element_t dr;   /* G_2 */ //dr = g^{gamma/beta}
	arsanvkabe_RRD_key_t* rrd_key; // struct arsanvkabe_RRD_key_s = GArray of bswabe_prv_comp_t

	/* Parameters related to the Dummy Attribute */
	element_t d_attd; /* G_2 */ // d_attd = g^{r+gamma}.H1(H2(attd + epsilon))^{r2}, where attd is the dummy attribute
	element_t t_attd  /* G_1 */ // t_attd = g^{r2}
};	


struct arsanvkabe_prv_comp_s
{
	/* these actually get serialized */
	char* attr; //char*
	element_t d;  /* G_2 */ //C_j
	element_t dp; /* G_1 */ //C_j'
};

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
 *Attribute Authority Secret Key Component
 */
struct arsanvkabe_AA_secret_key_s
{
	GArray* skAA;
};


/*
 * user private key in fahdabe
 */
typedef struct arsanvkabe_prv_user_s arsanvkabe_prv_user_t;


/*
 * Resource-Rich Device Component in fahdabe to aggregate all the Attribute 
 *  Authority Secret Key Components belonging to a specific data user (DU) (an array of skAA_t)
 */
typedef struct arsanvkabe_RRD_key_s arsanvkabe_RRD_key_t;

/*
 * Attribute Authority Secret Component
 */
typedef struct arsanvkabe_AA_secret_key_s skAA_t;

/*
 * user public subkey sent to the resource-rich device 
 * to realize partial decryption (by extension applying revocation updates) 
 */
typedef struct arsanvkabe_user_rrd_subkey_s user_RRD_t;


