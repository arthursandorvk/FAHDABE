/*
 * keygen3.h
 *
 *  Created on: Nov 23, 2023
 *      Author: Arthur Sandor
 */

// Attribute structure in BSW-CPABE
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


/* Attribute Authority Secret Key Component */
struct arsanvkabe_AA_secret_key_s
{
	GArray* skAA;
};


/* RRD key made of an array of AA Keys */
struct arsanvkabe_RRD_key_s
{
	GArray* AAkey_array;
};

typedef struct arsanvkabe_RRD_key_s arsanvkabe_RRD_key_t;

/* Attribute Authority Secret Component */

typedef struct arsanvkabe_AA_secret_key_s skAA_t;


arsanvkabe_RRD_key_t* arsanvkabe_keygen3(bswabe_pub_t* pub, GArray *fileAAList, element_t du_blind);
GByteArray* arsanvkabe_prv_rrdKey_serialize(arsanvkabe_RRD_key_t* rrd_key);
void arsanvkabe_RRD_key_t_free(arsanvkabe_RRD_key_t* rrd_key);
