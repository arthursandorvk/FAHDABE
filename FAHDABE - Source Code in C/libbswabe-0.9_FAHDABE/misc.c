#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <pbc.h>
#include <assert.h>
#define PBC_DEBUG /* to enable debug builds */

#include "bswabe.h"
#include "private.h"

//----------------------------------------------------------------------

void serialize_uint32( GByteArray* b, uint32_t k )
{
	int i;
	guint8 byte;

	for( i = 3; i >= 0; i-- )
	{
		byte = (k & 0xff<<(i*8))>>(i*8);
		g_byte_array_append(b, &byte, 1);
	}
}

//----------------------------------------------------------------------

uint32_t unserialize_uint32( GByteArray* b, int* offset )
{
	int i;
	uint32_t r;

	r = 0;
	for( i = 3; i >= 0; i-- )
		r |= (b->data[(*offset)++])<<(i*8);

	return r; 

}

//----------------------------------------------------------------------

void serialize_element( GByteArray* b, element_t e )
{
	uint32_t len;
	unsigned char* buf;

	len = element_length_in_bytes(e);
	serialize_uint32(b, len);

	buf = (unsigned char*) malloc(len);
	element_to_bytes(buf, e);
	g_byte_array_append(b, buf, len);
	free(buf);
}

//----------------------------------------------------------------------

void unserialize_element( GByteArray* b, int* offset, element_t e )
{
	uint32_t len;

	unsigned char* buf;
	
	if (!b)
	{
		g_error("Failed to open buffer, buffer might be empty");
	}

	len = unserialize_uint32(b, offset);

	buf = (unsigned char*) malloc(len*sizeof(unsigned char));
	
	memcpy(buf, b->data + *(offset), len);
	
	*offset += len;

	element_from_bytes(e, buf);
	
	free(buf);
}

//----------------------------------------------------------------------

void serialize_string( GByteArray* b, char* s )
{
	g_byte_array_append(b, (unsigned char*) s, strlen(s) + 1);
}

//-----------------------------------------------------------------------

char* unserialize_string( GByteArray* b, int* offset )
{
	GString* s;
	char* r;
	char c;

	s = g_string_sized_new(32);
	while( 1 )
	{
		c = b->data[(*offset)++];
		if( c && c != EOF )
			g_string_append_c(s, c);
		else
			break;
	}

	r = s->str;
	g_string_free(s, 0);

	return r;
}

//-------------------------------------------------------------------------

GByteArray* bswabe_pub_serialize( bswabe_pub_t* pub )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_string(b,  pub->pairing_desc);
	serialize_element(b, pub->g);
	serialize_element(b, pub->h);
	serialize_element(b, pub->gp);
	serialize_element(b, pub->g_hat_alpha);
	serialize_element(b, pub->f);
	serialize_element(b, pub->y_no_hat);
	
	return b;
}

//------------------------------------------------------------------------------

bswabe_pub_t* bswabe_pub_unserialize( GByteArray* b, int free )
{
	bswabe_pub_t* pub;
	int offset;

	pub = (bswabe_pub_t*) malloc(sizeof(bswabe_pub_t));
	offset = 0;

	pub->pairing_desc = unserialize_string(b, &offset);
	pairing_init_set_buf(pub->p, pub->pairing_desc, strlen(pub->pairing_desc));

	element_init_G1(pub->g,           pub->p);
	element_init_G1(pub->h,           pub->p);
	element_init_G1(pub->gp,          pub->p);
	element_init_GT(pub->g_hat_alpha, pub->p);

	element_init_G1(pub->f,           pub->p);
	element_init_GT(pub->y_no_hat,	  pub->p);

	unserialize_element(b, &offset, pub->g);
	unserialize_element(b, &offset, pub->h);
	unserialize_element(b, &offset, pub->gp);
	unserialize_element(b, &offset, pub->g_hat_alpha);

	unserialize_element(b, &offset, pub->f);
	unserialize_element(b, &offset, pub->y_no_hat);
	

	if( free )
		g_byte_array_free(b, 1);

	return pub;
}

//--------------------------------------------------------------------------------

GByteArray* bswabe_msk_serialize( bswabe_msk_t* msk )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_element(b, msk->beta);
	serialize_element(b, msk->g_alpha);

	return b;
}

//--------------------------------------------------------------------------------

bswabe_msk_t* bswabe_msk_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	bswabe_msk_t* msk;
	int offset;

	msk = (bswabe_msk_t*) malloc(sizeof(bswabe_msk_t));
	offset = 0;

	element_init_Zr(msk->beta, pub->p);
	element_init_G1(msk->g_alpha, pub->p);

	unserialize_element(b, &offset, msk->beta);
	unserialize_element(b, &offset, msk->g_alpha);

	if( free )
		g_byte_array_free(b, 1);

	return msk;
}

//------------------------------------------------------------------------------

/*
 * To serialize the attribute authority secret key from a GByteArray into a file 
 */
GByteArray* arsanvkabe_prv_AA_serialize( skAA_t* prv )
{
	GByteArray* b;
	
	int i; /* index */

	b = g_byte_array_new();

	serialize_uint32( b, prv->skAA->len); /* Serializing number of elements */
	
	for( i = 0; i < prv->skAA->len; i++ )
	{
		serialize_string(b, g_array_index(prv->skAA, struct bswabe_prv_comp_t, i).attr);
		serialize_element(b, g_array_index(prv->skAA, struct bswabe_prv_comp_t, i).d);
		serialize_element(b, g_array_index(prv->skAA, struct bswabe_prv_comp_t, i).dp);
	}
	return b;
}

//---------------------------------------------------------------------------------------------------------------

/*
 * To compute the unserialize the attribut authority secret key AA_key from a GByteArray
 */
skAA_t* arsanvkabe_prv_AA_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
   	skAA_t* prv;
	int i;
	int len;
	int offset;

	prv = (skAA_t*) malloc(sizeof(skAA_t));
	
	prv->skAA = g_array_new(0, 1, sizeof(bswabe_prv_comp_t));

	offset = 0;
	
	len = unserialize_uint32(b, &offset);
	
	for( i = 0; i < len; i++ )
	{
		struct bswabe_prv_comp_t c;

		c.attr = unserialize_string(b, &offset);

		element_init_G1(c.d,  pub->p);
		unserialize_element(b, &offset, c.d);
		
		element_init_G1(c.dp, pub->p);
		unserialize_element(b, &offset, c.dp);

		g_array_append_val(prv->skAA, c);
	}

	if( free )
		g_byte_array_free(b, 1);

	return prv;
}

//-----------------------------------------------------------------------------------------------------

/*
 * To serialize the secret key component from Data Owner (DO_key) into a file
 */
GByteArray* arsanvkabe_prv_do_serialize( arsanvkabe_prv_do_t* prv )
{
	GByteArray* b;
	int i;

	b = g_byte_array_new();
		
	serialize_element(b, prv->d);
	serialize_element(b, prv->du_blind);
	serialize_element(b, prv->hkey);
	serialize_string(b, prv->epsilon_digest_string);

	/* Serializing the dummy attribute */
	serialize_uint32( b, prv->dummy_attr_array->len);

	
	for( i = 0; i < prv->dummy_attr_array->len; i++ )
	{
		serialize_string( b, g_array_index(prv->dummy_attr_array, arsanvkabe_prv_comp_t, i).attr);
		serialize_element(b, g_array_index(prv->dummy_attr_array, arsanvkabe_prv_comp_t, i).d);
		serialize_element(b, g_array_index(prv->dummy_attr_array, arsanvkabe_prv_comp_t, i).dp);
	}

	return b;
}

//-------------------------------------------------------------------------------------------------------------

/*
 * To unserialize the DO_key from a GByteArray
 */
arsanvkabe_prv_do_t* arsanvkabe_prv_do_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	arsanvkabe_prv_do_t* prv;

	int i;
	int len;
	int offset;
	offset = 0;

	prv = (arsanvkabe_prv_do_t*) malloc(sizeof(arsanvkabe_prv_do_t));
	
	element_init_G1(prv->d, pub->p);
	unserialize_element(b, &offset, prv->d);	

	element_init_G1(prv->du_blind, pub->p);
	unserialize_element(b, &offset, prv->du_blind);

	element_init_G1(prv->hkey, pub->p);
	unserialize_element(b, &offset, prv->hkey);
	

	prv->epsilon_digest_string = unserialize_string(b, &offset);

	/* unserializing the dummy attribute */
	prv->dummy_attr_array = g_array_new(0, 1, sizeof(arsanvkabe_prv_comp_t));
	len = unserialize_uint32(b, &offset);
	for( i = 0; i < len; i++ )
	{
		arsanvkabe_prv_comp_t c; /* structure for dummy attribute */

		c.attr = unserialize_string(b, &offset);

		element_init_G1(c.d,  pub->p);
		unserialize_element(b, &offset, c.d);
		
		element_init_G1(c.dp, pub->p);
		unserialize_element(b, &offset, c.dp);

		g_array_append_val(prv->dummy_attr_array, c);
	}
	if( free )
		g_byte_array_free(b, 1);

    return prv;
}

//-------------------------------------------------------------------------------------------------------------------------------

/*
 * To serialize the DO epsilon structure down to a GByteArray
 */
GByteArray* arsanvkabe_do_epsilon_serialize(arsanvkabe_epsilon_t* DO_epsilon)
{
	GByteArray* b;

	b = g_byte_array_new();
	
	serialize_string(b, DO_epsilon->epsilon_string);
	serialize_string(b, DO_epsilon->epsilon_digest_string);

	return b;
}

//--------------------------------------------------------------------------------------------------------------------------------

/*
 * To unserialize the DO epsilon structure from a GByteArray
 */
arsanvkabe_epsilon_t* arsanvkabe_do_epsilon_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	arsanvkabe_epsilon_t* DO_epsilon = 0;
	
	int offset;
	offset=0;
	
	DO_epsilon = (arsanvkabe_epsilon_t*)malloc(sizeof(arsanvkabe_epsilon_t));
	
	DO_epsilon->epsilon_string = unserialize_string(b, &offset);
	DO_epsilon->epsilon_digest_string = unserialize_string(b, &offset);
	
	if( free )
		g_byte_array_free(b, 1);

	return DO_epsilon;
}

//---------------------------------------------------------------------------------------------------------------

/*
 * To serialize the RRD key
 */
GByteArray* arsanvkabe_prv_rrdKey_serialize(arsanvkabe_RRD_key_t* rrd_key)
{
	GByteArray* b;
	
	int i;
	
	b = g_byte_array_new();
	
	serialize_uint32(b,rrd_key->AAkey_array->len);

	for( i = 0; i < rrd_key->AAkey_array->len; i++ )
	{
		serialize_string(b, g_array_index(rrd_key->AAkey_array, struct bswabe_prv_comp_t, i).attr);
		serialize_element(b, g_array_index(rrd_key->AAkey_array, struct bswabe_prv_comp_t, i).d);
		serialize_element(b, g_array_index(rrd_key->AAkey_array, struct bswabe_prv_comp_t, i).dp);
	}
	
	return b;
}	

//---------------------------------------------------------------------------------------------------------------

/*
 * To unserialize the RRD key
 */
arsanvkabe_RRD_key_t* arsanvkabe_prv_rrdKey_unserialize (bswabe_pub_t* pub, GByteArray* b, int free)
{
	arsanvkabe_RRD_key_t *rrd_key=0;

	int i=0;

	int rrd_key_len;

	rrd_key = (arsanvkabe_RRD_key_t*)malloc(sizeof(arsanvkabe_RRD_key_t));
	
	rrd_key->AAkey_array = g_array_new(0, 1, sizeof(bswabe_prv_comp_t)); 
	
	int offset;
	offset = 0;
	
	rrd_key_len = unserialize_uint32(b, &offset);
	
	int number_bswabe_prv_compt=0;
	
	for( i = 0; i < rrd_key_len; i++ )
	{
		struct bswabe_prv_comp_t c;

		c.attr = unserialize_string(b, &offset);
		
		element_init_G1(c.d,  pub->p);
		unserialize_element(b, &offset, c.d);

		element_init_G1(c.dp, pub->p);
		unserialize_element(b, &offset, c.dp);

		g_array_append_val(rrd_key->AAkey_array, c);

		number_bswabe_prv_compt++;

	} //extracting every skAA_t

	if( free )
		g_byte_array_free(b, 1);

	return rrd_key;
}
		
//-----------------------------------------------------------------------------------------------------------

/*
 * To serialize the complete user Secret Key
 */
GByteArray* arsanvkabe_prv_userSK_serialize(arsanvkabe_prv_user_t* prv )
{
    	GByteArray* b;
	
	int i;
	b = g_byte_array_new();

	/* Serializing the DO key */	
	serialize_element(b, prv->D->d);
	
	serialize_element(b, prv->D->hkey);
	
	serialize_uint32( b, prv->D->dummy_attr_array->len);

	for( i = 0; i < prv->D->dummy_attr_array->len; i++ )
	{
		serialize_string( b, g_array_index(prv->D->dummy_attr_array, arsanvkabe_prv_comp_t, i).attr);
		serialize_element(b, g_array_index(prv->D->dummy_attr_array, arsanvkabe_prv_comp_t, i).d);
		serialize_element(b, g_array_index(prv->D->dummy_attr_array, arsanvkabe_prv_comp_t, i).dp);
	}
	
	/* Serializing the RRD key */
	serialize_uint32(b, prv->U->AAkey_array->len);

	for( i = 0; i < prv->U->AAkey_array->len; i++ )
	{
		serialize_string(b, g_array_index(prv->U->AAkey_array, struct bswabe_prv_comp_t, i).attr);
		serialize_element(b, g_array_index(prv->U->AAkey_array, struct bswabe_prv_comp_t, i).d);
		serialize_element(b, g_array_index(prv->U->AAkey_array, struct bswabe_prv_comp_t, i).dp);
	}
	
	return b;
}

//---------------------------------------------------------------------------------------------------------------

/*
 * To unserialize the complete user secret key that includes DO key and the RRD key
 */
arsanvkabe_prv_user_t* arsanvkabe_prv_user_unserialize(bswabe_pub_t* pub, GByteArray* b, int free)
{
	arsanvkabe_prv_user_t *prv=0;
	
	int offset;

	offset=0; 

	prv = (arsanvkabe_prv_user_t*)malloc(sizeof(arsanvkabe_prv_user_t));

	int j;

	int doKey_len;
	
	prv->D = (arsanvkabe_prv_do_t*) malloc(sizeof(arsanvkabe_prv_do_t));
	
	/* Unserializing the DO key */
	element_init_G1(prv->D->d, pub->p);
	unserialize_element(b, &offset, prv->D->d);

	element_init_G1(prv->D->hkey, pub->p);
	unserialize_element(b, &offset, prv->D->hkey);	

	/* unserializing dummy attribute in DO key */
	prv->D->dummy_attr_array = g_array_new(0, 1, sizeof(arsanvkabe_prv_comp_t));
	
	doKey_len = unserialize_uint32(b, &offset);

	for( j = 0; j < doKey_len; j++ )
	{
		arsanvkabe_prv_comp_t c;

		c.attr = unserialize_string(b, &offset);

		element_init_G1(c.d,  pub->p);
		unserialize_element(b, &offset, c.d);

		element_init_G1(c.dp, pub->p);
		unserialize_element(b, &offset, c.dp);

		g_array_append_val(prv->D->dummy_attr_array, c);
	}
	
	/* Unserializing the RRD key */
	int i=0;

	int rrd_key_len;

	prv->U = (arsanvkabe_RRD_key_t*)malloc(sizeof(arsanvkabe_RRD_key_t));
	//
	prv->U->AAkey_array = g_array_new(0, 1, sizeof(bswabe_prv_comp_t));

	rrd_key_len = unserialize_uint32(b, &offset);

	int number_bswabe_prv_compt=0;
	
	for( i = 0; i < rrd_key_len; i++ )
	{
		struct bswabe_prv_comp_t c;

		c.attr = unserialize_string(b, &offset);
	
		element_init_G1(c.d,  pub->p);
		unserialize_element(b, &offset, c.d);
		
		element_init_G1(c.dp, pub->p);
		unserialize_element(b, &offset, c.dp);
		
		g_array_append_val(prv->U->AAkey_array, c);

		/* Uncomment to count the number of attributes */
		//number_bswabe_prv_compt++; 
	}

	if( free )
		g_byte_array_free(b, 1);

	return prv;
}

//----------------------------------------------------------------------------------------------------------------------

/*
 * To serialize the DU_Out_key, which is the user's public subkey used by the RRD, into a GBYteArray
 */
GByteArray* arsanvkabe_User_RRD_subKey_serialize(user_RRD_t* DU_Out_key)
{
	GByteArray* b;

	int i=0;

	b = g_byte_array_new();
	
	serialize_element(b, DU_Out_key->dr);
	serialize_element(b, DU_Out_key->d_attd);
	serialize_element(b, DU_Out_key->t_attd);

	/* DU_Out_key includes the rrd_key*/
	serialize_uint32(b, DU_Out_key->rrd_key->AAkey_array->len);

	for( i = 0; i < DU_Out_key->rrd_key->AAkey_array->len; i++ )
	{
		serialize_string(b, g_array_index(DU_Out_key->rrd_key->AAkey_array, struct bswabe_prv_comp_t, i).attr);
		serialize_element(b, g_array_index(DU_Out_key->rrd_key->AAkey_array, struct bswabe_prv_comp_t, i).d);
		serialize_element(b, g_array_index(DU_Out_key->rrd_key->AAkey_array, struct bswabe_prv_comp_t, i).dp);
	}
	
	return b;
}

//---------------------------------------------------------------------------------------------------------------------

/*
 * To unserialize the DU_Out_key, which is the user's public subkey used by the RRD, from a GBYteArray
 */
user_RRD_t* arsanvkabe_User_RRD_subKey_unserialize(bswabe_pub_t* pub, GByteArray* b, int free)
{
	user_RRD_t* DU_Out_key=0;
	
	int offset;
	
	DU_Out_key = (user_RRD_t*)malloc(sizeof(user_RRD_t));

	element_init_G1(DU_Out_key->dr, pub->p);
	element_init_G1(DU_Out_key->d_attd, pub->p);
	element_init_G1(DU_Out_key->t_attd, pub->p);

	offset=0;
	
	/* user secret key component to help the outsourced decryption */
	unserialize_element(b, &offset, DU_Out_key->dr);

	/* Extracting dummy attribute key parameters */
	unserialize_element(b, &offset, DU_Out_key->d_attd);

	unserialize_element(b, &offset, DU_Out_key->t_attd);

	/* Extracting the rrd_key*/
	int i=0;
	int rrd_key_len;

	DU_Out_key->rrd_key = (arsanvkabe_RRD_key_t*)malloc(sizeof(arsanvkabe_RRD_key_t));

	DU_Out_key->rrd_key->AAkey_array = g_array_new(0, 1, sizeof(bswabe_prv_comp_t));
	
	rrd_key_len = unserialize_uint32(b, &offset);

	int number_bswabe_prv_compt=0;
	
	for( i = 0; i < rrd_key_len; i++ )
	{
		struct bswabe_prv_comp_t c;
		c.attr = unserialize_string(b, &offset);

		element_init_G1(c.d,  pub->p);
		unserialize_element(b, &offset, c.d);

		element_init_G1(c.dp, pub->p);
		unserialize_element(b, &offset, c.dp);
	
		g_array_append_val(DU_Out_key->rrd_key->AAkey_array, c);
		number_bswabe_prv_compt++;
	}

	if( free )
		g_byte_array_free(b, 1);

	return DU_Out_key;
}

//---------------------------------------------------------------------------------------------------------------------

/*
 * To serialize the first stage arsanvkabe_cph_DO_t ciphertext CT_DO into a GBYteArray
 */
GByteArray* arsanvkabe_cph_DO_serialize(arsanvkabe_cph_DO_t* cph_DO )
{
	GByteArray* b;
	
	b = g_byte_array_new();
	
	serialize_element(b, cph_DO->cs);
	
	serialize_element(b, cph_DO->c);
	
	serialize_element(b, cph_DO->g_s2);
	
	serialize_element(b, cph_DO->c_attd);
	
	serialize_element(b, cph_DO->witness);
	
	serialize_string(b, cph_DO->p);

	return b;
}

//----------------------------------------------------------------------------------------------------------------

/*
 * To unserialize the first stage arsanvkabe_cph_DO_t ciphertext CT_DO from a GBYteArray
 */
arsanvkabe_cph_DO_t* arsanvkabe_cph_DO_unserialize(bswabe_pub_t* pub, GByteArray* b, int free )
{
	arsanvkabe_cph_DO_t* cph_DO;
	
	int offset;
	
	cph_DO = (arsanvkabe_cph_DO_t*) malloc(sizeof(arsanvkabe_cph_DO_t));
		
	offset = 0;
	
	element_init_GT(cph_DO->cs,  pub->p);
	
	element_init_G1(cph_DO->c,  pub->p);
	
	element_init_G1(cph_DO->g_s2,  pub->p);
	
	element_init_G1(cph_DO->c_attd,  pub->p);
	
	element_init_GT(cph_DO->witness,  pub->p);
	
	cph_DO->p = 0;

	unserialize_element(b, &offset, cph_DO->cs);
	
	unserialize_element(b, &offset, cph_DO->c);
	
	unserialize_element(b, &offset, cph_DO->g_s2);

	unserialize_element(b, &offset, cph_DO->c_attd);

	unserialize_element(b, &offset, cph_DO->witness);
	
	cph_DO->p = unserialize_string(b, &offset);

	if( free )
		g_byte_array_free(b, 1);

	return cph_DO;
}

//---------------------------------------------------------------------------------------------------------------

/*
 * To serialize the second stage arsanvkabe_cph_RRD_t ciphertext CT_RRD into a GBYteArray
 */
GByteArray* arsanvkabe_cph_RRD_serialize(arsanvkabe_cph_RRD_t* cph_RRD )
{
	GByteArray* b;
	
	b = g_byte_array_new();
	
	serialize_element(b, cph_RRD->cs);
	
	serialize_element(b, cph_RRD->c);
	
	serialize_element(b, cph_RRD->cs_do);
	
	serialize_element(b, cph_RRD->c_do);
	
	serialize_element(b, cph_RRD->gs2_do);
	
	serialize_element(b, cph_RRD->c_attd_do);
	
	serialize_element(b, cph_RRD->witness);
	
	serialize_policy(b, cph_RRD->p);

	return b;
}

//---------------------------------------------------------------------------------------------------------------

/*
 * To unserialize the second stage arsanvkabe_cph_RRD_t ciphertext CT_RRD from a GBYteArray
 */
arsanvkabe_cph_RRD_t* arsanvkabe_cph_RRD_unserialize(bswabe_pub_t* pub, GByteArray* b, int free )
{
	arsanvkabe_cph_RRD_t* cph_RRD;
	
	int offset;
	
	cph_RRD = (arsanvkabe_cph_RRD_t*) malloc(sizeof(arsanvkabe_cph_RRD_t));
		
	offset = 0;
	
	element_init_GT(cph_RRD->cs,  pub->p);
	
	element_init_G1(cph_RRD->c,  pub->p);

	element_init_GT(cph_RRD->cs_do,  pub->p);

	element_init_G1(cph_RRD->c_do,  pub->p);

	element_init_G1(cph_RRD->gs2_do,  pub->p);

	element_init_G1(cph_RRD->c_attd_do,  pub->p);

	element_init_GT(cph_RRD->witness,  pub->p);

	cph_RRD->p = (struct bswabe_policy_t*) malloc(sizeof(struct bswabe_policy_t));
		
	unserialize_element(b, &offset, cph_RRD->cs);
	
	unserialize_element(b, &offset, cph_RRD->c);
	
	unserialize_element(b, &offset, cph_RRD->cs_do);
	
	unserialize_element(b, &offset, cph_RRD->c_do);
	
	unserialize_element(b, &offset, cph_RRD->gs2_do);
	
	unserialize_element(b, &offset, cph_RRD->c_attd_do);
	
	unserialize_element(b, &offset, cph_RRD->witness);

	cph_RRD->p = unserialize_policy(pub, b, &offset);
	
	if( free )
		g_byte_array_free(b, 1);

	return cph_RRD;

}

//----------------------------------------------------------------------------------------------------------------

/* 
 * To serialize the access policy on the RRD side
 */
void serialize_policy( GByteArray* b, struct bswabe_policy_t* p )
{
	int i;

	serialize_uint32(b, (uint32_t) p->k);

	serialize_uint32(b, (uint32_t) p->children->len);

	if( p->children->len == 0 )
	{
		serialize_string( b, p->attr);

		serialize_element(b, p->c);

		serialize_element(b, p->cp);
	}
	else
		for( i = 0; i < p->children->len; i++ )
		{
			serialize_policy(b, g_ptr_array_index(p->children, i));
		}
			
}

/* 
 * To serialize the access policy on the RRD side
 */
struct bswabe_policy_t* unserialize_policy( bswabe_pub_t* pub, GByteArray* b, int* offset )
{
	int i;
	int n;
	struct bswabe_policy_t* p;

	p = (struct bswabe_policy_t*) malloc(sizeof(struct bswabe_policy_t));

	p->k = (int) unserialize_uint32(b, offset);
	p->attr = 0;
	p->children = g_ptr_array_new();

	n = unserialize_uint32(b, offset);
	if( n == 0 )
	{
		p->attr = unserialize_string(b, offset);
		element_init_G1(p->c,  pub->p);
		element_init_G1(p->cp, pub->p);
		unserialize_element(b, offset, p->c);
		unserialize_element(b, offset, p->cp);
	}
	else
		for( i = 0; i < n; i++ )
			g_ptr_array_add(p->children, unserialize_policy(pub, b, offset));

	return p;
}

/* 
 * BSW-CP-ABE function to serialize ciphertext
 */
GByteArray* bswabe_cph_serialize( bswabe_cph_t* cph )
{
	GByteArray* b;

	b = g_byte_array_new();
	serialize_element(b, cph->cs);
	serialize_element(b, cph->c);
	serialize_policy( b, cph->p);

	return b;
}

/* 
 * BSW-CP-ABE function to unserialize ciphertext
 */
bswabe_cph_t* bswabe_cph_unserialize( bswabe_pub_t* pub, GByteArray* b, int free )
{
	bswabe_cph_t* cph;
	int offset;

	cph = (bswabe_cph_t*) malloc(sizeof(bswabe_cph_t));
	offset = 0;

	element_init_GT(cph->cs, pub->p);
	element_init_G1(cph->c,  pub->p);
	unserialize_element(b, &offset, cph->cs);
	unserialize_element(b, &offset, cph->c);
	cph->p = unserialize_policy(pub, b, &offset);

	if( free )
		g_byte_array_free(b, 1);

	return cph;
}

/* 
 * BSW-CP-ABE functions to free resources
 */
void bswabe_pub_free( bswabe_pub_t* pub )
{
	element_clear(pub->g);
	element_clear(pub->h);
	element_clear(pub->gp);
	element_clear(pub->g_hat_alpha);
	element_clear(pub->f);
	element_clear(pub->y_no_hat);
	pairing_clear(pub->p);
	free(pub->pairing_desc);
	free(pub);
}


void bswabe_msk_free( bswabe_msk_t* msk )
{
	element_clear(msk->beta);
	element_clear(msk->g_alpha);
	free(msk);
}

void bswabe_prv_free( bswabe_prv_t* prv )
{
	int i;
	
	element_clear(prv->d);

	for( i = 0; i < prv->comps->len; i++ )
	{
		struct bswabe_prv_comp_t c;

		c = g_array_index(prv->comps, struct bswabe_prv_comp_t, i);
		free(c.attr);
		element_clear(c.d);
		element_clear(c.dp);
	}

	g_array_free(prv->comps, 1);

	free(prv);
}

void bswabe_policy_free( struct bswabe_policy_t* p )
{
	int i;

	if( p->attr )
	{
		free(p->attr);
		element_clear(p->c);
		element_clear(p->cp);
	}

	for( i = 0; i < p->children->len; i++ )
		bswabe_policy_free(g_ptr_array_index(p->children, i));

	g_ptr_array_free(p->children, 1);

	free(p);
}

void bswabe_cph_free( bswabe_cph_t* cph )
{
	element_clear(cph->cs);
	element_clear(cph->c);
	bswabe_policy_free(cph->p);
}

/*to free the CT_RRD*/
void arsanvkabe_cph_rrd_free( arsanvkabe_cph_RRD_t* cph )
{
	element_clear(cph->cs); 
	element_clear(cph->c); 
	bswabe_policy_free(cph->p);
	element_clear(cph->gs2_do);
	element_clear(cph->cs_do);
	element_clear(cph->c_do); 
	element_clear(cph->witness);
}

/*to free the CT_DO*/
void arsanvkabe_cph_do_free( arsanvkabe_cph_DO_t* cph )
{
	element_clear(cph->cs); 
	element_clear(cph->c);
	element_clear(cph->g_s2);  
	free(cph->p); 
	element_clear(cph->witness);
}

/* to free the DO key arsanvkabe_prv_do_t*/
void arsanvkabe_prv_do_t_free( arsanvkabe_prv_do_t* do_key )
{
	element_clear(do_key->d); 
	element_clear(do_key->du_blind);
	free(do_key->epsilon_digest_string);
	g_array_free(do_key->dummy_attr_array, 1);
}

/* to free a dummy attribute struct variable arsanvkabe_prv_comp_t */
void arsanvkabe_prv_comp_t_free( arsanvkabe_prv_comp_t* dummy_attr )
{
	element_clear(dummy_attr->d); 
	element_clear(dummy_attr->dp); 
	free(dummy_attr->attr);
}

/* to free attribute authority secret key*/
void skAA_t_free(skAA_t* AA_key)
{
	g_array_free(AA_key->skAA, 1);
}

/* to free the rrdKey of type arsanvkabe_RRD_key_t*/
void arsanvkabe_RRD_key_t_free(arsanvkabe_RRD_key_t* rrd_key)
{
	g_array_free(rrd_key->AAkey_array, 1);
}

/* to free the complete user key */
void arsanvkabe_prv_user_t_free(arsanvkabe_prv_user_t* userSK)
{
	arsanvkabe_prv_do_t_free(userSK->D);
	arsanvkabe_RRD_key_t_free(userSK->U);
}

/* to free the public user subkey */
void user_RRD_t_free(user_RRD_t* DU_Out_key)
{
	element_clear(DU_Out_key->dr);
	arsanvkabe_RRD_key_t_free(DU_Out_key->rrd_key);
}
