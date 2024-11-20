/*
 *	Include glib.h, pbc.h, and bswabe.h before including this file.
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

//-------------------------------------------------------------------------------------------------------------------------------------------

struct bswabe_msk_s
{
	element_t beta;    /* Z_r */
	element_t g_alpha; /* G_2 */ 
};

//-------------------------------------------------------------------------------------------------------------------------------------------

struct bswabe_prv_comp_t
{
	/* these actually get serialized */
	char* attr; 
	element_t d;  /* G_2 */ //C_j
	element_t dp; /* G_2 */ //C_j'

	/* only used during dec (only by dec_merge) */
	int used;
	element_t z;  /* G_1 */
	element_t zp; /* G_1 */
};

//-------------------------------------------------------------------------------------------------------------------------------------------

struct arsanvkabe_prv_comp_s
{
	/* these actually get serialized */
	char* attr; //char* /* Uncomment and perform necessary adjustments to include the value of the dummy attribute */
	element_t d;  /* G_2 */ //C_j
	element_t dp; /* G_1 */ //C_j'
};

//-------------------------------------------------------------------------------------------------------------------------------
struct bswabe_prv_s
{
	element_t d;   /* G_2 */
	GArray* comps; /* bswabe_prv_comp_t's */
};

//-------------------------------------------------------------------------------------------------------------------------------------------

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

//-------------------------------------------------------------------------------------------------------------------------------------------

/*
 *Attribute Authority Secret Key Component
 */
struct arsanvkabe_AA_secret_key_s
{
	GArray* skAA;
};

//-------------------------------------------------------------------------------------------------------------------------------------------

/*
 *RRD key made of a GByteArray of AAKeys
 */
struct arsanvkabe_RRD_key_s
{
	GArray* AAkey_array;
};

//-------------------------------------------------------------------------------------------------------------------------------------------

/*
 * Complete user secret key
 */
struct arsanvkabe_prv_user_s
{
	arsanvkabe_prv_do_t* D; /* partial key issued by DO*/
	arsanvkabe_RRD_key_t* U; /* partial key issued by RRD */
};

//-------------------------------------------------------------------------------------------------------------------------------------------

/*
 * User public subkey DO_Out_key sent to RRD for policy evaluation and partial decryption
 */
struct arsanvkabe_user_rrd_subkey_s
{
	element_t dr;   /* G_2 */ 
	arsanvkabe_RRD_key_t* rrd_key; /* GArray of bswabe_prv_comp_t */

	/* Parameters related to the Dummy Attribute */
	element_t d_attd; /* G_2 */ 
	element_t t_attd  /* G_1 */
};	


//-------------------------------------------------------------------------------------------------------------------------------------------

/*
 * first stage ciphertext from encryption by DO
 */
struct arsanvkabe_cph_DO_s
{
	element_t cs; /* G_T */
	element_t c;  /* G_1 */
	element_t g_s2;  /* G_1 */
	element_t c_attd; /* G_2 */
	char* p; /* anonymized access policy */
	element_t witness; // sort of proof of ownership (like digital signature)
};

//-------------------------------------------------------------------------------------------------------------------------------------------

/*
 * second stage ciphertext from encryption by RRD (Resource-Rich Device)
 */
struct arsanvkabe_cph_RRD_s
{
	element_t cs; /* G_T */ 
	element_t c;  /* G_1 */
	struct bswabe_policy_t* p; // anonymized access policy built on the BSW CP-ABE policy structure

	/* Existing parameters from DO ciphertext */
	element_t gs2_do;  /* G_1 */
	element_t cs_do; /* G_T */
	element_t c_do;  /* G_1 */
	element_t c_attd_do; /* G_2*/
	element_t witness; /* DO issued ciphertext Proof */
};

//--------------------------------------------------------------------------------------------------------------------------------------------

/*
 * DO structure for attribute masking factor epsilon
 */
struct arsanvkabe_epsilon_s
{
	char* epsilon_string; /* will be kept private by DO */
	char* epsilon_digest_string; /*H2(epsilon)*/ /* Will be included in DU partial key*/
};

//--------------------------------------------------------------------------------------------------------------------------------------------

struct bswabe_polynomial_t
{
	int deg;
	/* coefficients from [0] x^0 to [deg] x^deg */
	element_t* coef; /* G_T (of length deg + 1) */
};

//-------------------------------------------------------------------------------------------------------------------------------------------

struct bswabe_policy_t
{
	/* serialized */
	int k;            /* one if leaf, otherwise threshold */
	char* attr;       /* attribute string if leaf, otherwise null */
	element_t c;      /* G_1, only for leaves *///ciphertext-> Cy
	element_t cp;     /* G_1, only for leaves */ //ciphertext -> Cy'
	GPtrArray* children; /* pointers to bswabe_policy_t's, len == 0 for leaves */

	/* only used during encryption */
	struct bswabe_polynomial_t* q;

	/* only used during decryption */
	int satisfiable;
	int min_leaves;
	int attri;
	GArray* satl;
};

//-------------------------------------------------------------------------------------------------------------------------------------------

struct bswabe_cph_s
{
	element_t cs; /* G_T */ // M=e(g,g)alpha*s
	element_t c;  /* G_1 */ // C= h^beta
	struct bswabe_policy_t* p;
};
