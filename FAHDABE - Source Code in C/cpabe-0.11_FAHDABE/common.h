/*
	Include glib.h and pbc.h before including this file.

	This contains data structures and procedures common throughout the
	tools.
*/

#include <openssl/aes.h>

#include <openssl/sha.h>




/* Preprocessor global variables*/

/* file hosting the structure of the attribute masking factor epsilon */
#define EPSILON_FILE "epsilon_DO_param" 

/* file containing hidden attributes */
#define DEFAULT_HIDDEN_ATTR_FILE "Hidden_Attr_File" 

/* file storing the value of h_rp to generate 
first stage ciphertext component for the dummy attribute */
#define ATTD_FOR_CTDO_FILE "CTDO_cattd"

/* Output file for the DO issued partial key */
#define DO_KEY_FILE "DO_key" 

/* Default file name for AA issued Attribute Authority secret key */
#define AA_KEY_FILE "AA_key"

/* Default file to contain the public user subkey necessary for 
outsourced operations on its behalf */
#define PUBLIC_USER_SUBKEY_FILE "DU_Out_key"

/* Default file to hold the complete user secret key */
#define USER_SECRET_KEY_FILE "user_key"

/* Output file for the rrd_key */
#define RRD_KEY_FILE "rrd_key"

/* Extension of DO generated ciphertext */
#define DO_CIPHERTEXT_EXTENSION ".ct_do"

/* Extension for Aes encryption of input file */
#define AES_ENCRYPTED_FILE_EXTENSION ".aes"

/* Extension of RRD generated ciphertext */
#define RRD_CIPHERTEXT_EXTENSION ".cpabe"

/* Name of File to store temporal results */
#define TEMPORAL_RESULTS_FILE_NAME "/home/summer/temp_skyfall.txt"

/* Name of File to store the access policy */
#define POLICY_FILE_NAME "policy.txt"

/*Name of File storing the user parameter to blind attribute keys */
#define DU_BLIND_PARAM_FILE_NAME "du_blind"

/*
	TODO if ssl sha1 not available, use built in one (sha1.c)
*/

char*       suck_file_str( char* file );

char*       suck_stdin();

GByteArray* suck_file( char* file );

void spit_file( char* file, GByteArray* b, int free );

void read_cpabe_file( char* file, GByteArray** cph_buf, int* file_len, GByteArray** aes_buf );

void write_cpabe_file( char* file, GByteArray* cph_buf, int file_len, GByteArray* aes_buf );

void die(char* fmt, ...);


/* To parse hidden attributes from File in KeygenAA */
void arsanvkabe_parse_attribute( GSList** l, char* a );

/* to write a GByteArray to a file */
void store_gbyte_array( GByteArray* b, const char *filename);

/* to read a GByteArray from a file */
GByteArray *load_gbyte_array(const char *filename);

/* AES encryption with seed k. */
GByteArray* aes_128_cbc_encrypt( GByteArray* pt, element_t k );

/* AES decryption with seed k */
GByteArray* aes_128_cbc_decrypt( GByteArray* ct, element_t k );


#define CPABE_VERSION PACKAGE_NAME "%s " PACKAGE_VERSION "\n" \
"\n" \
"This work updates the original CP-ABE of John Bethencourt, Amit Shahai and Brent Waters\n" \
"There is NO warranty; not even for MERCHANTABILITY or FITNESS\n" \
"FOR A PARTICULAR PURPOSE.\n" \
"Report bugs to Arthur Sandor Voundi <sandorvoundi@xidian.edu.cn>.\n" \
"Original Notice:Parts Copyright (C) 2006, 2007 John Bethencourt and SRI International.\n" \
"This is free software released under the GPL, see the source for copying\n" \
"conditions. There is NO warranty; not even for MERCHANTABILITY or FITNESS\n" \
"FOR A PARTICULAR PURPOSE.\n" \
"\n" \
"Report bugs to John Bethencourt <bethenco@cs.berkeley.edu>.\n"
