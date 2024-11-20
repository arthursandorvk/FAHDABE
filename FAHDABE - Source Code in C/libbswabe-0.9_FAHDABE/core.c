#include <stdlib.h>
#include <string.h>
#include <math.h>

//we include POSIX Shared memory libraries
#include <sys/mman.h>
#include  <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include <errno.h> # to access errno and strerror


#ifndef BSWABE_DEBUG
#define NDEBUG
#define PBC_DEBUG //to enable debug builds
#endif

/* Parameters of the underlying Lattice used that refer to LThash16 but can be extended */
#define LATTICE_DIMENSION 8 //the dimension of LTHASH Lattice
#define LATTICE_DEGREE 10 // the degree of the lattice = square root the determininant of the lattice basis matrix 

/* paremeters linked to buffer sizes in invoking python command */
#define PYTHON_COMMAND_BUFFER_SIZE 500
#define PYTHON_COMMAND_RESULT_BUFFER_SIZE 200 /* Buffer size to store the returned result */


#include <assert.h>
#include <openssl/sha.h>
#include <pbc.h>
#include <glib.h>
#include "bswabe.h"
#include "private.h"


/*
 *this is the A type of pairings in PBC
 */
#define TYPE_A_PARAMS \
"type a\n" \
"q 87807107996633125224377819847540498158068831994142082" \
"1102865339926647563088022295707862517942266222142315585" \
"8769582317459277713367317481324925129998224791\n" \
"h 12016012264891146079388821366740534204802954401251311" \
"822919615131047207289359704531102844802183906537786776\n" \
"r 730750818665451621361119245571504901405976559617\n" \
"exp2 159\n" \
"exp1 107\n" \
"sign1 1\n" \
"sign0 1\n"
//----------------------------------------------------------------------------


/*
 *we declare curve parameters for the F pairing type on Barreto Naherig Curve
 */
#define TYPE_F_PARAMS \
"type f\n" \
"q 205523667896953300194896352429254920972540065223\n" \
"r 205523667896953300194895899082072403858390252929\n" \
"b 40218105156867728698573668525883168222119515413\n" \
"beta 115334401956802802075595682801335644058796914268\n" \
"alpha0 191079354656274778837764015557338301375963168470\n" \
"alpha1 71445317903696340296199556072836940741717506375\n" 


//--------------------------------------------------------------------------
char last_error[256];

char* bswabe_error()
{
	return last_error;
}

void raise_error(char* fmt, ...)
{
	va_list args;

#ifdef BSWABE_DEBUG
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(1);
#else
	va_start(args, fmt);
	vsnprintf(last_error, 256, fmt, args);
	va_end(args);
#endif
}
//-----------------------------------------------------------------------------


/*
 * This function computes the LTHash value of a string input and returns the string version of the resulting vector (Since LtHash operates over Lattices)
 */
char* compute_Lthash_return_string(char* input_string)
{
	char command_python[PYTHON_COMMAND_BUFFER_SIZE];

	
	/*feel free to add the path to the directory containing the script here or 
	u can also add it directly to the Shared PATH with: export PATH=$PATH:/path/to/script/directory on Linux UBuntu */
	char python_script[] ="/home/summer/Documents/Github/Utility_FAHDABE/fahdabe-lthash-compute.py";

	snprintf(command_python, sizeof(command_python), "python3 %s %d %d %s", python_script, LATTICE_DIMENSION, LATTICE_DEGREE, input_string);
	
	FILE *fp = popen(command_python, "r");	

	// the output of the lthash_digest
	int array_size = PYTHON_COMMAND_RESULT_BUFFER_SIZE;
	
	char* LThash_Output = malloc(array_size * sizeof(char));
		
	int string_length = 0;	
	
	//expand the array as needed
	int ch;
	
	while ((ch = fgetc(fp)) != EOF)	
	{
		LThash_Output[string_length++] = ch;
		
		// double the capacity if the buffer becomes full
		if (string_length >= array_size)// -1)
		{
			array_size *= 2;
			//
			LThash_Output = realloc(LThash_Output, array_size * sizeof(char));			
		}
	}
	pclose(fp);
	
	LThash_Output[string_length] = '\0';

	// trim the excess allocation of memory
	return realloc(LThash_Output, (string_length+1)* sizeof(char));

}

//-----------------------------------------------------------------------------------------------------------------------------

/*
 * This function computes the LTHash value of two input strings and returns a char*
 */
char* compute_Lthash_Add_inputs_return_string(char* input1, char* input2)
{
	char command_python[PYTHON_COMMAND_BUFFER_SIZE];
	
	char python_script[] ="/home/summer/Documents/Github/Utility_FAHDABE/fahdabe-lthash-addValues.py";


	snprintf(command_python, sizeof(command_python), "python3 %s %d %d %s %s", python_script, LATTICE_DIMENSION, LATTICE_DEGREE, input1, input2);

	FILE *fp = popen(command_python, "r");	

	int array_size = PYTHON_COMMAND_RESULT_BUFFER_SIZE;

	char* LThash_Output = malloc(array_size * sizeof(char)); 

	int string_length = 0;	

	int ch;

	while ((ch = fgetc(fp)) != EOF)	
	{
		LThash_Output[string_length++] = ch;

		if (string_length >= array_size -1)
		{
			array_size *= 2;
			//
			LThash_Output = realloc(LThash_Output, array_size * sizeof(char));			
		}
	
	}
	pclose(fp);

	LThash_Output[string_length] = '\0';

	return realloc(LThash_Output, (string_length+1)* sizeof(char));
}

//--------------------------------------------------------------------------------------------------------------------------------

/*
 * This function reads H2(epsilon) from a temporary file: temp_skyfall.txt to exploit such value later 
 * and outputs a digest 
 * Such digest is stored within the file for temporary storage. and the second input as string
 * It returns the char* expression of the resulting digest
 */
char* compute_Lthash_Digest_hidden_epsilon(char* input2)
{
	char command_python[PYTHON_COMMAND_BUFFER_SIZE];
	
	char python_script[] ="/home/summer/Documents/Github/Utility_FAHDABE/fahdabe-lthash-add_hash_data.py";

	/* Make sure the first input is the string expression of a vector that represents a LTHash digest*/
	snprintf(command_python, sizeof(command_python), "python3 %s %d %d %s", python_script, LATTICE_DIMENSION, LATTICE_DEGREE, input2);

	FILE *fp = popen(command_python, "r");	

	int array_size = PYTHON_COMMAND_RESULT_BUFFER_SIZE;

	char* LThash_Output = malloc(array_size * sizeof(char));

	int string_length = 0;	

	int ch;

	while ((ch = fgetc(fp)) != EOF)	
	{
		LThash_Output[string_length++] = ch;

		if (string_length >= array_size -1)
		{
			array_size *= 2;
			//
			LThash_Output = realloc(LThash_Output, array_size * sizeof(char));			
		}
	
	}
	pclose(fp);

	LThash_Output[string_length] = '\0';

	return realloc(LThash_Output, (string_length+1)* sizeof(char));
}

//--------------------------------------------------------------------------------------------------------------------------------

/* 
 *computes the SHA256 digest of a string input and outputs the digest as a string
 */
char* compute_String_sha256(char* input)
{
	assert((input != NULL) && (strlen(input)) > 0);

	char hash[SHA256_DIGEST_LENGTH +1];

	SHA256_CTX ctx;
	SHA256_Init(&ctx);

	SHA256_Update(&ctx, input, strlen(input));
 	SHA256_Final(hash, &ctx);

	char* hex_output = malloc(2* SHA256_DIGEST_LENGTH + 1);
	
	if(!hex_output)
	{
		return NULL;
	}

	int i;
	for(i=0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(hex_output + (i * 2), "%02x", hash[i]);
	}

	hex_output[SHA256_DIGEST_LENGTH*2] = '\0';

	return hex_output;
}

//-----------------------------------------------------------------------------------------------------------------------------

// This function H3: GT ---> {0,1}^l takes a pairing in GT and returns a non-bijective string expression
char* pairing_to_string(element_t GTpairing)
{
	
	char* r;
	unsigned int sizePairing;
	// get the size of bytes of the element
	uint32_t bytes_amount;
	bytes_amount=element_length_in_bytes(GTpairing);
	// initialize the unsigned char to hold the corresponding byte value 
	r = (char*) malloc(bytes_amount);
	
	element_snprint(r, bytes_amount, GTpairing);

	// extract the bytes value
	//element_to_bytes(r, GTpairing);
	// Compute the corresponding digest to ensure a fixed output size and at the same time convert the output to a string value
	unsigned char* output_hashed;
	output_hashed =  compute_String_sha256(r);
	free(r);
	//return the correspponding non bijective string;
	//return output;
	
	return output_hashed;
}


/*
 *benchmarking function to estimate the cost of exponentation, multiplication and pairing operations in G1 and G2
 */

//---------------------------------------Benchmarking our system---------------------------------------------------------------
int pbc_benchmark(bswabe_pub_t* pub)
{
	//variables to store the time
	double expG1low, expG1high, expG2low, expG2high, expGTlow, expGThigh, mulG1low, mulG1high, mulG2low, mulG2high, mulGTlow, mulGThigh, pairGTlow, pairGThigh, expG0low, expG0high, mulG0low, mulG0high;
	//
	element_t v; /*G1*/
	element_t g; /*G1*/

	element_t h; /*G2*/
	element_t u; /*G2*/

	element_t a; /*Zr*/

	element_t pp; /*GT*/

	//initialization
	element_init_G1(v,	          pub->p);	
	element_init_G1(g,	          pub->p);

	element_init_G2(h,	          pub->p);
	element_init_G2(u,	          pub->p);
	
	element_init_Zr(a,		  	  pub->p);
	element_init_GT(pp, 		  pub->p);

	//computations + time collection
	element_random(v);	
	element_random(g);

	element_random(h);
	element_random(u);

	element_random(a);
	

	//exponentiation in G1
	expG1low = clock();//pbc_get_time();
	element_pow_zn(g, g, a);
	expG1high = clock();//pbc_get_time();
	double resultExpG1 = ((expG1high - expG1low)*1000);
	printf("Average PBC Exponentiation in G1 is %f ms; result of  %f - %f \n", resultExpG1/CLOCKS_PER_SEC, expG1high, expG1low );
	
	//exponentiation in G2
	expG2low = clock();//pbc_get_time();
	element_pow_zn(h, h, a);
	expG2high = clock();//pbc_get_time();
	double resultExpG2 = ((expG2high - expG2low)*1000);
	printf("Average PBC Exponentiation in G2 is %f ms; result of  %f - %f \n",resultExpG2/CLOCKS_PER_SEC, expG2high, expG2low);

	
	//multiplication in G1
	mulG1low = clock();//pbc_get_time();
	element_mul(g, g, v);
	mulG1high = clock();//pbc_get_time();
	double resultMulG1 = ((mulG1high - mulG1low)*1000);
	printf("Average PBC Multiplication in G1 is %f ms ;result of  %f - %f \n", resultMulG1/CLOCKS_PER_SEC, mulG1high, mulG1low);
	

	//multiplication in G2
	mulG2low = clock();//pbc_get_time();
	element_mul(h, h, u);
	mulG2high = clock();//;pbc_get_time();	
	double resultMulG2 = ((mulG2high - mulG2low)*1000);
	printf("Average PBC Multiplication in G2 is %f ms ;result of  %f - %f \n", resultMulG2/CLOCKS_PER_SEC, mulG2high, mulG2low);
	
	
	//pairing in GT
	pairGTlow = clock();//pbc_get_time();
	pairing_apply(pp, g, h, pub->p);
	pairGThigh = clock();//pbc_get_time();
	double resultPairGT = ((pairGThigh - pairGTlow)*1000);
	printf("Average PBC Pairing in asymetric GT is %f ms; result of  %f - %f \n",resultPairGT/CLOCKS_PER_SEC, pairGThigh, pairGTlow);

	//exponentiation in GT
	expGTlow = clock();//pbc_get_time();
	element_pow_zn(pp, pp, a);
	expGThigh = clock();//pbc_get_time();
	double resultExpGT = ((expGThigh - expGTlow)*1000);
	printf("Average PBC Exponentiation in GT is %f ms; result of  %f - %f \n",resultExpGT/CLOCKS_PER_SEC, expGThigh, expGTlow);
	
	//multiplication in GT
	mulGTlow = clock();//pbc_get_time();
	element_mul(pp, pp, pp);
	mulGThigh = clock();//;pbc_get_time();	
	double resultMulGT = ((mulGThigh - mulGTlow)*1000);
	printf("Average PBC Multiplication in GT is %f ms ;result of  %f - %f \n", resultMulGT/CLOCKS_PER_SEC, mulGThigh, mulGTlow);
	

	//garbage collector
	element_clear(g);
	element_clear(h);
	element_clear(a);
	element_clear(pp);

	return 0;
	
}
//-------------------------------------------End of system benchmarking----------------------------------------------------------





//-------------------------------------------End of system benchmarking----------------------------------------------------------

/*
 * This function deterministically generates an element_t from a string ( implemented as random oracle in the security model)
 * You can set the resulting value to be part of a finite field or an elliptic curve by defining ahead of calling the domain of h
 */
void element_from_string( element_t h, char* s )
{
	unsigned char* r;

	r = malloc(SHA_DIGEST_LENGTH);
	SHA1((unsigned char*) s, strlen(s), r);
	element_from_hash(h, r, SHA_DIGEST_LENGTH);

	free(r);
	/*
	// uncomment to use the Sha256 hash function (the above uses the SHA-160)
	
	char* hashedValue=0;
	hashedValue = compute_String_sha256(s);
	
	element_from_hash(h, hashedValue, (SHA256_DIGEST_LENGTH * 2 + 1));
	*/
	
}

//-------------------------------------------------------------------------------------------------------------------------------

void bswabe_setup( bswabe_pub_t** pub, bswabe_msk_t** msk )
{
	element_t alpha;

	/* initialize */
	*pub = malloc(sizeof(bswabe_pub_t));
	*msk = malloc(sizeof(bswabe_msk_t));
	
	(*pub)->pairing_desc = strdup(TYPE_A_PARAMS); //symmetric pairing

	pairing_init_set_buf((*pub)->p, (*pub)->pairing_desc, strlen((*pub)->pairing_desc)); 

	//initialize our variables with (*pub)->p, which serves as pairing description
	element_init_G1((*pub)->g,           (*pub)->p);
	element_init_G1((*pub)->h,           (*pub)->p);
	element_init_G2((*pub)->gp,          (*pub)->p);
	element_init_GT((*pub)->g_hat_alpha, (*pub)->p);
	element_init_Zr(alpha,               (*pub)->p);
	element_init_Zr((*msk)->beta,        (*pub)->p);
	element_init_G2((*msk)->g_alpha,     (*pub)->p);
	element_init_G2((*pub)->f,           (*pub)->p);
	element_init_GT((*pub)->y_no_hat,    (*pub)->p);
	
	/* compute */
 	element_random(alpha);
 	element_random((*msk)->beta);
	element_random((*pub)->g);
	
	element_random((*pub)->gp);

	element_pow_zn((*msk)->g_alpha, (*pub)->gp, alpha); /*G1*/

	element_pow_zn((*pub)->h, (*pub)->g, (*msk)->beta); /*G1*/

 	pairing_apply((*pub)->g_hat_alpha, (*pub)->g, (*msk)->g_alpha, (*pub)->p); /*GT*/

	element_t beta_inv;
	element_init_Zr(beta_inv, (*pub)->p);
	element_invert(beta_inv, (*msk)->beta); /*Zp*/

	element_pow_zn((*pub)->f, (*pub)->gp, beta_inv);  /*G2*/

	pairing_apply((*pub)->y_no_hat, (*pub)->g, (*pub)->gp, (*pub)->p); /*GT*/

	/*	
	printf("We test the element from hash\n\n");
	char mygid[100] = "gid";
	
	element_t gidZp;
	element_init_Zr(gidZp, (*pub)->p);
	element_from_string(gidZp, mygid); 
	element_printf("value of gidZp is %B \n\n", gidZp);
	
	element_t g_exp_gidZp;
	element_init_G1(g_exp_gidZp,  (*pub)->p); 
	element_pow_zn(g_exp_gidZp, (*pub)->g, gidZp );
	element_printf("value of g_exp_gidZp is %B \n\n", g_exp_gidZp);

	element_t gidG1;
	element_init_G1(gidG1,  (*pub)->p);
	element_from_string(gidG1, mygid); 
	element_printf("value of gidG1 is %B \n\n", gidG1);
	*/


	//free beta_inv
	element_clear(beta_inv);
}

//------------------------------------------------------------------------------------------------------

/*
 * arsanvkabe_keygen0 
 * To generate DO atribute masking factor epsilon structure that will be used to enforce attribute hiding
 */
arsanvkabe_epsilon_t* arsanvkabe_keygen0( bswabe_pub_t* pub, char* epsilon_string_value )
{	
	arsanvkabe_epsilon_t* DO_epsilon;
	DO_epsilon = (arsanvkabe_epsilon_t*) malloc(sizeof(arsanvkabe_epsilon_t));
	
	DO_epsilon->epsilon_string = epsilon_string_value;

	/* implements H2(epsilon)*/
	DO_epsilon->epsilon_digest_string = compute_Lthash_return_string(epsilon_string_value);
	
	return DO_epsilon;
} 

//------------------------------------------------------------------------------------------------------

/*
 * arsanvkabe_keygen1 
 * To generate the secret key DO_key component
 */
arsanvkabe_prv_do_t* arsanvkabe_keygen1( bswabe_pub_t* pub, bswabe_msk_t* msk, char* user_gid, char** dummy_attributes, arsanvkabe_epsilon_t* do_epsilon )
{
	/* secret key component to be returned */	
	arsanvkabe_prv_do_t *priv; 
	
	/* local randomness parameters to embed alpha and beta to user keys (BSW_CP-ABE)*/
	element_t g_r;
	element_t r; 
	
	/* to prevent attribute collusion */
	element_t gamma; 
	element_t beta_inv; 
	element_t du_blind; /* du_blind = gp^(r+gamma) */

	/* Ephemeral variables */
	element_t r_plus_gamma;
	element_t gamma_div_beta;
	
	
	/* initialize */
	priv = (arsanvkabe_prv_do_t*)malloc(sizeof(arsanvkabe_prv_do_t));

	priv->dummy_attr_array = g_array_new(0, 1, sizeof(arsanvkabe_prv_comp_t));
	
	element_init_G2(priv->d, pub->p); /*G2*/
	element_init_G2(g_r, pub->p); /*G2*/	
	element_init_G2(priv->du_blind, pub->p); /*G2*/
	element_init_G2(priv->hkey, pub->p); /*G2*/
	
	element_init_Zr(r, pub->p); /*Zp*/
	element_init_Zr(beta_inv, pub->p); /*Zp*/
	element_init_Zr(gamma, pub->p); /*Zp*/

	element_init_Zr(gamma_div_beta, pub->p); /*Zp*/
	element_init_Zr(r_plus_gamma, pub->p); /*Zp*/
	
	
	
    	/* compute */
 	element_random(r);
	
	element_from_string(gamma, user_gid);


	/* computing priv->du_blind */
	element_add(r_plus_gamma, r, gamma); 
	element_pow_zn(priv->du_blind, pub->gp, r_plus_gamma);


	/*computing priv->hkey */
	element_div(gamma_div_beta, gamma, msk->beta);
	element_pow_zn(priv->hkey, pub->gp, gamma_div_beta);
	

	/* computing priv->d */
	element_pow_zn(g_r, pub->gp, r);
	element_mul(priv->d, msk->g_alpha, g_r); 
	element_invert(beta_inv, msk->beta);
	element_pow_zn(priv->d, priv->d, beta_inv);


	/* Assigning the epsilon digest value H2(epsilon) to DO key */
	priv->epsilon_digest_string = do_epsilon->epsilon_digest_string;


	/*Processing the dummy attributes (only the first one in this work) */
	while( *dummy_attributes )
	{
		arsanvkabe_prv_comp_t c; /* dummy attribute structure */
		element_t h_rp;
		element_t rp;

		/*Initialization of variables*/		
		element_init_G2(c.d,  pub->p);
		element_init_G1(c.dp, pub->p);
		element_init_G2(h_rp, pub->p);
		element_init_Zr(rp,   pub->p);

		c.attr = *(dummy_attributes++);
		

		/* masking the dummy attribute value. DO has access to the plain expression of epsilon  */
		c.attr = compute_Lthash_Add_inputs_return_string(c.attr, do_epsilon->epsilon_string); /* computing H2(c.attr + epsilon) */
	
		element_t z_c_attr;
		element_init_Zr(z_c_attr, pub->p);
		element_from_string(z_c_attr, c.attr); 


		//element_from_string(h_rp, c.attr);
		element_pow_zn(h_rp, pub->gp, z_c_attr); 

 		element_random(rp); /* Zp */ /* individual attribute randomness */
		
		element_pow_zn(c.d, h_rp, rp);/* G1 */

		/* Update component c.d of the dummy attribute with du_blind */
		element_mul(c.d, c.d, priv->du_blind); /* G1 */ 
		element_pow_zn(c.dp, pub->g, rp); /* G1 */
		
		/* freeing memory */
		element_clear(h_rp);
		element_clear(rp);
		element_clear(z_c_attr);

		g_array_append_val(priv->dummy_attr_array, c);

		break; /* Comment if your work supports multiple dummy attributes */
	}
	return priv;
}

//---------------------------------------------------------------------------------------------------------------

/*
 *  arsanvkabe_keygen2 
 * To generate Attribute Authority Secret Key for a given set of attributes by a given AA 
 * Number of Executions = Number of sollicited AAs. 
 * => If three attribute authorities, run arsanvkabe_keygenAA thrice
 */
skAA_t* arsanvkabe_keygen2(bswabe_pub_t* pub, char** attributes, char* user_gid)
{

	skAA_t* prv=0; /* Attribute Authority Secret Key */

	/* initializing */
	prv = (skAA_t*)malloc(sizeof(skAA_t));
	prv->skAA = g_array_new(0, 1, sizeof(struct bswabe_prv_comp_t));

	/* converting the user id into field element in Zp*/
	element_t gid;
	element_init_Zr(gid, pub->p);
	element_from_string(gid, user_gid);


	/* Processing each attribute provided */
	while( *attributes )
	{
		bswabe_prv_comp_t c;

		element_t h_rp; /*G2*/

		element_t rp; /*Zp*/
		
		
		element_init_G2(h_rp, pub->p);
		element_init_G2(c.d,  pub->p);
		element_init_G2(c.dp, pub->p);
		element_init_Zr(rp, pub->p);
		
		/* the current attribute value has been hidden by user when running cpabe-hide_attr*/
		c.attr = *(attributes++);

		element_t z_c_attr;
		element_init_Zr(z_c_attr, pub->p);
		element_from_string(z_c_attr, c.attr); 


		//element_from_string(h_rp, c.attr);
		element_pow_zn(h_rp, pub->gp, z_c_attr); 
 		
		element_random(rp); /* attribute individual randomness */

		/* computation of c.d */
		element_pow_zn(c.d, h_rp, rp); /*G1*/

		element_pow_zn(h_rp, h_rp, gid); /*G1*/

		element_pow_zn(h_rp, h_rp, rp); /*G1*/
		
		// we update c.d
		element_mul(c.d, c.d, h_rp); /*G1*/



		/* computation of c.dp */
		element_pow_zn(c.dp, pub->gp, rp); /*G2*/

		// computation of g^{rp*gid} in G2
		element_t g_exp_gid;
		element_init_G2(g_exp_gid, pub->p);
		element_pow_zn(g_exp_gid, pub->gp, gid); /*G2*/
		element_pow_zn(g_exp_gid, g_exp_gid, rp); /*G2*/

		// we update c.dp 
		element_mul(c.dp, c.dp, g_exp_gid); /*G2*/
          		
		/* freeing variables*/		
		element_clear(h_rp);
		element_clear(rp);
			
		g_array_append_val(prv->skAA, c);
	}
		return prv;
}

//-------------------------------------------------------------------------------------------------------------------

/*
 *to fetch the Attribute Authority Secret Key from the file on disk
 */
skAA_t* fetchSKAA(bswabe_pub_t* pub, char *file)
{
    skAA_t* prv=0; //the pointer on the Attribute Authority Secret Key to be returned
	
    GByteArray* content = 0;
    content = load_gbyte_array(file);

    if (content == NULL)
	{
		die(bswabe_error());
	}	
    else
	{
    	prv= arsanvkabe_prv_AA_unserialize(pub, content, 1);
	}
	
    return prv;
}

//---------------------------------------------------------------------------------------------------------------------

/*
 * arsanvkabe_hide
 * To allow Data users to hide their attributes prior to requesting attribute keys from AAs
 */
char** arsanvkabe_hide(bswabe_pub_t* pub, char** attributes)
{
	int index=0;
	char* current_attribute = 0;

	/* processing attributes to hide one by one */
	for( int i=0; attributes[i] != NULL; i++ )
	{
		current_attribute = attributes[i];
		
		current_attribute = compute_Lthash_Digest_hidden_epsilon(current_attribute);

		gsize attr_length = strlen(current_attribute);

		/* Remove a possible leading and  trailing newline */
		attributes[i] = g_strstrip(current_attribute);

	} // end of for

	return attributes;
}

//---------------------------------------------------------------------------------------------------------------------

/*
 * arsanvkabe_keygen3
 * To aggregate AA secret keys from different Attribute Authorities (AAs) and update each attribute with share randomness to prevent user collusion
 */
arsanvkabe_RRD_key_t* arsanvkabe_keygen3(bswabe_pub_t* pub, GArray *fileAAList, element_t du_blind)
{
   
    arsanvkabe_RRD_key_t *rrdKey =0; /* resource-rich device key to be returned */

	/* initialization */
    rrdKey = (arsanvkabe_RRD_key_t*)malloc(sizeof(arsanvkabe_RRD_key_t));
    rrdKey->AAkey_array = g_array_new(0, 1, sizeof(struct bswabe_prv_comp_t));

	/* processing the various filenames in fileAAList */
    int sizeArray = fileAAList->len; 
    int i, j; /* indexes */

    for(i=0; i<sizeArray; i++)
    {
		skAA_t *localAAskey = 0;

		/* uncomment to access the name of the file containing the AA secret key */
		/*
			char *value=0;
			value = g_array_index(fileAAList,char*,i);
		*/

		/* Extracting each filename containing an AA key*/
		localAAskey=fetchSKAA(pub, g_array_index(fileAAList, char*, i));

		/* Atomic extraction of attributes key parameters. each attribute is of type bswabe_prv_comp_t 
		(except dummy attributes) */
		for (j=0; j<localAAskey->skAA->len; j++)
		{
			/* extracting key parameters for a single attribute */
			struct bswabe_prv_comp_t localVar; 
			localVar = g_array_index(localAAskey->skAA, struct bswabe_prv_comp_t, j);

			/* Updating each attribute with shared randomness du_blind provided by DO */
			element_mul(localVar.d, localVar.d, du_blind);

			/* Storing each single attribute with updated key parameters into rrdKey*/
			g_array_append_val(rrdKey->AAkey_array, localVar);
		}
    }

    return rrdKey;
}

//------------------------------------------------------------------------------------------------------------------------------------------------

/*
 * arsanvkabe_keygen4
 * Construct the user final secret key using the DO key and the RRD key
 */
arsanvkabe_prv_user_t* arsanvkabe_keygen4(bswabe_pub_t* pub)
{   
   arsanvkabe_prv_user_t *userSKey=0; //the user secret key

   int i=0;

   userSKey = (arsanvkabe_prv_user_t*)malloc(sizeof(arsanvkabe_prv_user_t));

   //functions in core.c should neither load nor store data except extreme situations so we do nothing here

   return userSKey;
}

//------------------------------------------------------------------------------------------------------------------------------------------------

/*
 * arsanvkabe_encrypt1
 * Compute DO ciphertxt 
 */
arsanvkabe_cph_DO_t* arsanvkabe_encrypt1( bswabe_pub_t* pub, element_t m, char* policy, element_t dummy_attr_element )
{
	arsanvkabe_cph_DO_t* cph_DO; //the ciphertext generated by DO

 	element_t s_2; /* secret to be shared on access tree with dummy node */

	/* initialize */
	cph_DO = (arsanvkabe_cph_DO_t*)malloc(sizeof(arsanvkabe_cph_DO_t));
	
	element_init_Zr(s_2, pub->p);
	
	element_init_GT(m, pub->p);
	
	element_init_GT(cph_DO->cs, pub->p);
	
	element_init_G1(cph_DO->c,  pub->p);

	element_init_G1(cph_DO->g_s2, pub->p);
	
	element_init_G2(cph_DO->c_attd, pub->p);

	element_init_GT(cph_DO->witness, pub->p);

	/* processing the hidden policy */
	cph_DO->p = policy;
	

	/* compute */

 	element_random(m); /* random Aes key */
	
 	element_random(s_2); /* random shared secret for T_{2}*/
	
	element_pow_zn(cph_DO->cs, pub->g_hat_alpha, s_2); 
	
	element_mul(cph_DO->cs, cph_DO->cs, m);
	
	element_pow_zn(cph_DO->c, pub->h, s_2);

	element_pow_zn(cph_DO->g_s2, pub->g, s_2); 
	
	element_pow_zn(cph_DO->c_attd, dummy_attr_element, s_2);
	


	// ephemeral variables
	element_t witness_term;
	element_init_GT(witness_term, pub->p);
	element_pow_zn(witness_term, pub->g_hat_alpha, s_2);
	element_mul(witness_term, cph_DO->cs, witness_term); /* M.e(g, gp)^{alpha.s2} . e(g, gp)^{alpha.s2} */
	
	unsigned char* str_from_pairing = 0;
 	str_from_pairing = pairing_to_string(witness_term); /* GT -> {0,1}^{L} */


	element_t dodis_yamplolskiy_exp;
	element_init_Zr(dodis_yamplolskiy_exp, pub->p);
	element_from_string(dodis_yamplolskiy_exp, str_from_pairing);
	element_invert(dodis_yamplolskiy_exp, dodis_yamplolskiy_exp); 


	/* We apply the somewhat modified construction from Dodis-Yampolskiy to compute the witness */
	element_pow_zn(cph_DO->witness, cph_DO->cs, dodis_yamplolskiy_exp);

	return cph_DO;
}

//----------------------------------------------------------------------------------------------------------------------------

/*
 * Compute the second stage of encryption by the RRD (Resource-Rich Device)
 */
//-----------------------------------------------------------------------------------------------------------------------------
arsanvkabe_cph_RRD_t* arsanvkabe_encrypt2(bswabe_pub_t* pub, element_t m, arsanvkabe_cph_DO_t* cph_DO)
{
	arsanvkabe_cph_RRD_t* cph_RRD=0; //the ciphertext generated by RRD

 	element_t s1; /* secret to be shared over the hidden access policy */

	/* initialize */	
	element_init_Zr(s1, pub->p);
	element_init_GT(m, pub->p); /* Aes key seed */
	cph_RRD = (arsanvkabe_cph_RRD_t*) malloc(sizeof(arsanvkabe_cph_RRD_t));
	element_init_GT(cph_RRD->cs, pub->p);
	element_init_G1(cph_RRD->c,  pub->p);
	element_init_GT(cph_RRD->cs_do, pub->p);
	element_init_G1(cph_RRD->c_do,  pub->p);
	element_init_G1(cph_RRD->gs2_do, pub->p);
	element_init_G2(cph_RRD->c_attd_do, pub->p); 
	element_init_GT(cph_RRD->witness, pub->p);
	cph_RRD->p = (struct bswabe_policy_t*) malloc(sizeof(struct bswabe_policy_t));

	
	/* compute */
 	element_random(s1);
	cph_RRD->p = parse_policy_postfix(cph_DO->p);
	element_pow_zn(cph_RRD->cs, pub->g_hat_alpha, s1); 
	element_mul(cph_RRD->cs, cph_RRD->cs, cph_DO->cs); 
	element_set(m, cph_DO->cs);
	element_pow_zn(cph_RRD->c, pub->h, s1);

	/* Same elements as cph_DO*/
	element_set(cph_RRD->cs_do, cph_DO->cs);
	element_set(cph_RRD->c_do, cph_DO->c);
	element_set(cph_RRD->gs2_do, cph_DO->g_s2);
	element_set(cph_RRD->c_attd_do, cph_DO->c_attd);
	element_set(cph_RRD->witness, cph_DO->witness);

	/* Polynomial secret sharing of s1 */
	fill_policy(cph_RRD->p, pub, s1); /* applying secret s1 over tree access structure by RRD */



	/* for monitoring */
	/* Unserializing the DO_key->du_blind */
	GByteArray* b_du_blind;
	b_du_blind = g_byte_array_new();
	b_du_blind = load_gbyte_array("/home/summer/Documents/Github16November2024/cpabe-0.11_FAHDABE/du_blind");

	element_t du_blind;
	element_init_G1(du_blind, pub->p);
	int offset;
	offset = 0;
	unserialize_element(b_du_blind, &offset, du_blind);

	element_t g_s1;
	element_init_G1(g_s1, pub->p);
	element_pow_zn(g_s1, pub->g, s1);

	element_t result_T;
	element_init_GT(result_T, pub->p);
	element_pairing(result_T, g_s1, du_blind);

	return cph_RRD;
}

//---------------------------------------------------------------------------------------------------

/*
 * Evaluate the hidden policy and compute the partial decryption result {T, I}
 */
int arsanvkabe_transform1( bswabe_pub_t* pub, user_RRD_t* DU_Out_key, arsanvkabe_cph_RRD_t* cph_rrd, element_t T, element_t I )
{
	bswabe_prv_t* prv=0; /* private key structure in BSW CP-ABE */

	/* Initialize */
	element_init_GT(T, pub->p);
	element_init_GT(I, pub->p);
	prv = (bswabe_prv_t*)malloc(sizeof(bswabe_prv_t));
	element_init_G2(prv->d, pub->p);
	prv->comps = g_array_new(0, 1, sizeof(struct bswabe_prv_comp_t));
	

	/* compute */
	element_set(prv->d, DU_Out_key->dr); /*G2*/
	prv->comps = DU_Out_key->rrd_key->AAkey_array; 	/* Append rrd_key attributes to prv->comps */


	/* Evaluating the hidden access policy */
	check_sat(cph_rrd->p, prv); 

	/* checking whether hidden policy has been matched */
	if( !cph_rrd->p->satisfiable )
	{
		raise_error("cannot decrypt, attributes in public User Subkey (DU_Out_key) fail to satisfy the hidden policy\n");
		return 0;
	}
	
	/* cross-term cancellation */
	pick_sat_min_leaves(cph_rrd->p, prv); 
	dec_flatten(T, cph_rrd->p, prv, pub); /* successful decryption outputs a GT group element as T */

	/* computing the additional I group element of GT */

	/* helper variables to compute additional I decryption result */
	element_t I_tempPairing_1;
	element_t I_tempPairing_2;
	element_t I_tempPairing_3; 
	element_t I_tempPairing_4;
	
	/* Initialize */
	element_init_GT(I_tempPairing_1, pub->p);
	element_init_GT(I_tempPairing_2, pub->p);
	element_init_GT(I_tempPairing_3, pub->p);
	element_init_GT(I_tempPairing_4, pub->p);

	/* Compute */
	element_pairing(I_tempPairing_1, cph_rrd->gs2_do, DU_Out_key->d_attd);  
	
	element_pairing(I_tempPairing_2, DU_Out_key->t_attd, cph_rrd->c_attd_do); 
	
	element_div(I_tempPairing_3, I_tempPairing_1, I_tempPairing_2);
	
	element_pairing(I_tempPairing_4, cph_rrd->c_do, DU_Out_key->dr);
	
	element_div(I, I_tempPairing_3, I_tempPairing_4);

	element_clear(I_tempPairing_1);
	element_clear(I_tempPairing_2);
	element_clear(I_tempPairing_3); 
	element_clear(I_tempPairing_4);
	
	return 1;
}

//---------------------------------------------------------------------------------------------------------------------------------------------------------------

struct bswabe_policy_t*
base_node( int k, char* s )
{
	struct bswabe_policy_t* p;

	p = (struct bswabe_policy_t*) malloc(sizeof(struct bswabe_policy_t));
	p->k = k;
	p->attr = s ? strdup(s) : 0;
	p->children = g_ptr_array_new();
	p->q = 0;

	return p;
}

/*
	TODO convert this to use a GScanner and handle quotes and / or
	escapes to allow attributes with whitespace or = signs in them
*/

struct bswabe_policy_t* parse_policy_postfix(char* s)
{
	char** toks;
	char** cur_toks;
	char*  tok;
	GPtrArray* stack; /* pointers to bswabe_policy_t's */
	struct bswabe_policy_t* root;

	toks     = g_strsplit(s, " ", 0);


	cur_toks = toks;
	
	stack    = g_ptr_array_new();

	while( *cur_toks )
	{
		int i, k, n;

		tok = *(cur_toks++);

		/* remove any trailing or leading space within each hidden attribute in the policy */
		tok = g_strstrip(tok);

		if( !*tok )
			continue;
		
		
		if( sscanf(tok, "%dof%d", &k, &n) != 2 )
		{
			g_ptr_array_add(stack, base_node(1, tok));
		}
		else
		{
			struct bswabe_policy_t* node;

			/* parse "kofn" operator */

			if( k < 1 )
			{
				raise_error("error parsing \"%s\": trivially satisfied operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( k > n )
			{
				raise_error("error parsing \"%s\": unsatisfiable operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( n == 1 )
			{
				raise_error("error parsing \"%s\": identity operator \"%s\"\n", s, tok);
				return 0;
			}
			else if( n > stack->len )
			{
				raise_error("error parsing \"%s\": stack underflow at \"%s\"\n", s, tok);
				return 0;
			}
			
			/* pop n things and fill in children */
			node = base_node(k, 0);
			g_ptr_array_set_size(node->children, n);
			for( i = n - 1; i >= 0; i-- )
				node->children->pdata[i] = g_ptr_array_remove_index(stack, stack->len - 1);
			
			/* push result */
			g_ptr_array_add(stack, node);
		}
	}

	if( stack->len > 1 )
	{
		raise_error("error parsing \"%s\": extra tokens left on stack\n", s);
		return 0;
	}
	else if( stack->len < 1 )
	{
		raise_error("error parsing \"%s\": empty policy\n", s);
		return 0;
	}

	root = g_ptr_array_index(stack, 0);

 	g_strfreev(toks);
 	g_ptr_array_free(stack, 0);

	return root;
}

struct bswabe_polynomial_t* rand_poly( int deg, element_t zero_val )
{
	int i;
	struct bswabe_polynomial_t* q;

	q = (struct bswabe_polynomial_t*) malloc(sizeof(struct bswabe_polynomial_t));
	
	q->deg = deg;
	
	q->coef = (element_t*) malloc(sizeof(element_t) * (deg + 1));
	

	for( i = 0; i < q->deg + 1; i++ )
		element_init_same_as(q->coef[i], zero_val);

	element_set(q->coef[0], zero_val);

	for( i = 1; i < q->deg + 1; i++ )
 		element_random(q->coef[i]);

	return q;
}

void
eval_poly( element_t r, struct bswabe_polynomial_t* q, element_t x )
{
	int i;
	element_t s, t;

	element_init_same_as(s, r);
	element_init_same_as(t, r);

	element_set0(r);
	element_set1(t);

	for( i = 0; i < q->deg + 1; i++ )
	{
		/* r += q->coef[i] * t */
		element_mul(s, q->coef[i], t);
		element_add(r, r, s);

		/* t *= x */
		element_mul(t, t, x);
	}

	element_clear(s);
	element_clear(t);
}

void
fill_policy( struct bswabe_policy_t* p, bswabe_pub_t* pub, element_t e )
{
	int i;
	element_t r;
	element_t t;
	element_t h;

	
	element_init_Zr(r, pub->p);
	
	element_init_Zr(t, pub->p);
	
	element_init_G2(h, pub->p);
	

	p->q = rand_poly(p->k - 1, e);
	

	if( p->children->len == 0 )
	{
		element_init_G1(p->c,  pub->p);
		element_init_G2(p->cp, pub->p);

		element_t z_p_attr;
		element_init_Zr(z_p_attr, pub->p);
		element_from_string(z_p_attr, p->attr);

		//element_from_string(h, p->attr);
		element_pow_zn(h, pub->g, z_p_attr);

		element_pow_zn(p->c,  pub->g, p->q->coef[0]);
		element_pow_zn(p->cp, h,      p->q->coef[0]);
		
	}
	else
	{
		for( i = 0; i < p->children->len; i++ )
		{
			element_set_si(r, i + 1);
			eval_poly(t, p->q, r);
			
			fill_policy(g_ptr_array_index(p->children, i), pub, t);
		}
	}
	
	element_clear(r);
	element_clear(t);
	element_clear(h);
}


void
check_sat( struct bswabe_policy_t* p, bswabe_prv_t* prv )
{
	int i, l;

	p->satisfiable = 0;
	if( p->children->len == 0 )
	{
		for( i = 0; i < prv->comps->len; i++ )
		{			
			/* Removing trailing space from the access policy, which might prevent attribute-policy matching*/
			if( !strcmp(g_array_index(prv->comps, struct bswabe_prv_comp_t, i).attr, p->attr) ) /* Remove some trailing and leading spaces */
			{
				p->satisfiable = 1;
				p->attri = i;
				break;
			}
		}
	}
	else
	{
		for( i = 0; i < p->children->len; i++ )
			check_sat(g_ptr_array_index(p->children, i), prv);

		l = 0;
		for( i = 0; i < p->children->len; i++ )
			if( ((struct bswabe_policy_t*) g_ptr_array_index(p->children, i))->satisfiable )
				l++;

		if( l >= p->k )
			p->satisfiable = 1;
	}
}

void
pick_sat_naive( struct bswabe_policy_t* p, bswabe_prv_t* prv )
{
	int i, k, l;

	assert(p->satisfiable == 1);

	if( p->children->len == 0 )
		return;

	p->satl = g_array_new(0, 0, sizeof(int));

	l = 0;
	for( i = 0; i < p->children->len && l < p->k; i++ )
		if( ((struct bswabe_policy_t*) g_ptr_array_index(p->children, i))->satisfiable )
		{
			pick_sat_naive(g_ptr_array_index(p->children, i), prv);
			l++;
			k = i + 1;
			g_array_append_val(p->satl, k);
		}
}

/* TODO there should be a better way of doing this */
struct bswabe_policy_t* cur_comp_pol;
int
cmp_int( const void* a, const void* b )
{
	int k, l;
	
	k = ((struct bswabe_policy_t*) g_ptr_array_index(cur_comp_pol->children, *((int*)a)))->min_leaves;
	l = ((struct bswabe_policy_t*) g_ptr_array_index(cur_comp_pol->children, *((int*)b)))->min_leaves;

	return
		k <  l ? -1 :
		k == l ?  0 : 1;
}

void
pick_sat_min_leaves( struct bswabe_policy_t* p, bswabe_prv_t* prv )
{
	int i, k, l;
	int* c;

	assert(p->satisfiable == 1);

	if( p->children->len == 0 )
		p->min_leaves = 1;
	else
	{
		for( i = 0; i < p->children->len; i++ )
			if( ((struct bswabe_policy_t*) g_ptr_array_index(p->children, i))->satisfiable )
				pick_sat_min_leaves(g_ptr_array_index(p->children, i), prv);

		c = alloca(sizeof(int) * p->children->len);
		for( i = 0; i < p->children->len; i++ )
			c[i] = i;

		cur_comp_pol = p;
		qsort(c, p->children->len, sizeof(int), cmp_int);

		p->satl = g_array_new(0, 0, sizeof(int));
		p->min_leaves = 0;
		l = 0;

		for( i = 0; i < p->children->len && l < p->k; i++ )
			if( ((struct bswabe_policy_t*) g_ptr_array_index(p->children, c[i]))->satisfiable )
			{
				l++;
				p->min_leaves += ((struct bswabe_policy_t*) g_ptr_array_index(p->children, c[i]))->min_leaves;
				k = c[i] + 1;
				g_array_append_val(p->satl, k);
			}
		assert(l == p->k);
	}
}

void
lagrange_coef( element_t r, GArray* s, int i )
{
	int j, k;
	element_t t;

	element_init_same_as(t, r);

	element_set1(r);
	for( k = 0; k < s->len; k++ )
	{
		j = g_array_index(s, int, k);
		if( j == i )
			continue;
		element_set_si(t, - j);
		element_mul(r, r, t); /* num_muls++; */
		element_set_si(t, i - j);
		element_invert(t, t);
		element_mul(r, r, t); /* num_muls++; */
	}

	element_clear(t);
}

void
dec_leaf_naive( element_t r, struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	struct bswabe_prv_comp_t* c;
	element_t s;

	c = &(g_array_index(prv->comps, struct bswabe_prv_comp_t, p->attri));

	element_init_GT(s, pub->p);

	pairing_apply(r, p->c,  c->d,  pub->p); /* num_pairings++; */
	pairing_apply(s, p->cp, c->dp, pub->p); /* num_pairings++; */
	element_invert(s, s);
	element_mul(r, r, s); /* num_muls++; */

	element_clear(s);
}

void dec_node_naive( element_t r, struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub );

//void
SHA256_CTX ctx; 
dec_internal_naive( element_t r, struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t s;
	element_t t;

	element_init_GT(s, pub->p);
	element_init_Zr(t, pub->p);

	element_set1(r);
	for( i = 0; i < p->satl->len; i++ )
	{
		dec_node_naive
			(s, g_ptr_array_index
			 (p->children, g_array_index(p->satl, int, i) - 1), prv, pub);
 		lagrange_coef(t, p->satl, g_array_index(p->satl, int, i));
		element_pow_zn(s, s, t); /* num_exps++; */
		element_mul(r, r, s); /* num_muls++; */
	}

	element_clear(s);
	element_clear(t);
}

void
dec_node_naive( element_t r, struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	assert(p->satisfiable);
	if( p->children->len == 0 )
		dec_leaf_naive(r, p, prv, pub);
	else
		dec_internal_naive(r, p, prv, pub);
}

void
dec_naive( element_t r, struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	dec_node_naive(r, p, prv, pub);
}

void
dec_leaf_merge( element_t exp, struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	struct bswabe_prv_comp_t* c;
	element_t s;

	c = &(g_array_index(prv->comps, struct bswabe_prv_comp_t, p->attri));

	if( !c->used )
	{
		c->used = 1;
		element_init_G1(c->z,  pub->p);
		element_init_G1(c->zp, pub->p);
		element_set1(c->z);
		element_set1(c->zp);
	}

	element_init_G1(s, pub->p);

	element_pow_zn(s, p->c, exp); /* num_exps++; */
	element_mul(c->z, c->z, s); /* num_muls++; */

	element_pow_zn(s, p->cp, exp); /* num_exps++; */
	element_mul(c->zp, c->zp, s); /* num_muls++; */

	element_clear(s);
}

void dec_node_merge( element_t exp, struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub );

void
dec_internal_merge( element_t exp, struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t t;
	element_t expnew;

	element_init_Zr(t, pub->p);
	element_init_Zr(expnew, pub->p);

	for( i = 0; i < p->satl->len; i++ )
	{
 		lagrange_coef(t, p->satl, g_array_index(p->satl, int, i));
		element_mul(expnew, exp, t); /* num_muls++; */
		dec_node_merge(expnew, g_ptr_array_index
									 (p->children, g_array_index(p->satl, int, i) - 1), prv, pub);
	}

	element_clear(t);
	element_clear(expnew);
}

void
dec_node_merge( element_t exp, struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	assert(p->satisfiable);
	if( p->children->len == 0 )
		dec_leaf_merge(exp, p, prv, pub);
	else
		dec_internal_merge(exp, p, prv, pub);
}

void
dec_merge( element_t r, struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t one;
	element_t s;

	/* first mark all attributes as unused */
	for( i = 0; i < prv->comps->len; i++ )
		g_array_index(prv->comps, struct bswabe_prv_comp_t, i).used = 0;

	/* now fill in the z's and zp's */
	element_init_Zr(one, pub->p);
	element_set1(one);
	dec_node_merge(one, p, prv, pub);
	element_clear(one);

	/* now do all the pairings and multiply everything together */
	element_set1(r);
	element_init_GT(s, pub->p);
	for( i = 0; i < prv->comps->len; i++ )
		if( g_array_index(prv->comps, struct bswabe_prv_comp_t, i).used )
		{
			struct bswabe_prv_comp_t* c = &(g_array_index(prv->comps, struct bswabe_prv_comp_t, i));

			pairing_apply(s, c->z, c->d, pub->p); /* num_pairings++; */
			element_mul(r, r, s); /* num_muls++; */

			pairing_apply(s, c->zp, c->dp, pub->p); /* num_pairings++; */
			element_invert(s, s);
			element_mul(r, r, s); /* num_muls++; */
		}
	element_clear(s);
}

void
dec_leaf_flatten( element_t r, element_t exp,
									struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	struct bswabe_prv_comp_t* c;
	element_t s;
	element_t t;

	c = &(g_array_index(prv->comps, struct bswabe_prv_comp_t, p->attri));

	element_init_GT(s, pub->p);
	element_init_GT(t, pub->p);

	pairing_apply(s, p->c,  c->d,  pub->p); /* num_pairings++; */
	pairing_apply(t, p->cp, c->dp, pub->p); /* num_pairings++; */
	element_invert(t, t);
	element_mul(s, s, t); /* num_muls++; */
	element_pow_zn(s, s, exp); /* num_exps++; */

	element_mul(r, r, s); /* num_muls++; */

	element_clear(s);
	element_clear(t);
}

void dec_node_flatten( element_t r, element_t exp,
											 struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub );

void
dec_internal_flatten( element_t r, element_t exp,
											struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	int i;
	element_t t;
	element_t expnew;

	element_init_Zr(t, pub->p);
	element_init_Zr(expnew, pub->p);

	for( i = 0; i < p->satl->len; i++ )
	{
 		lagrange_coef(t, p->satl, g_array_index(p->satl, int, i));
		element_mul(expnew, exp, t); /* num_muls++; */
		dec_node_flatten(r, expnew, g_ptr_array_index
										 (p->children, g_array_index(p->satl, int, i) - 1), prv, pub);
	}

	element_clear(t);
	element_clear(expnew);
}

void
dec_node_flatten( element_t r, element_t exp,
									struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	assert(p->satisfiable); // if any error an exception will be raised
	if( p->children->len == 0 )
		dec_leaf_flatten(r, exp, p, prv, pub);
	else
		dec_internal_flatten(r, exp, p, prv, pub);
}

void
dec_flatten( element_t r, struct bswabe_policy_t* p, bswabe_prv_t* prv, bswabe_pub_t* pub )
{
	element_t one;

	element_init_Zr(one, pub->p);

	element_set1(one);
	element_set1(r);

	dec_node_flatten(r, one, p, prv, pub);

	element_clear(one);
}
