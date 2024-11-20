#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <glib.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <pbc.h>
#include <assert.h>
#include <math.h>


#include "common.h"


void
init_aes( element_t k, int enc, AES_KEY* key, unsigned char* iv )
{
  int key_len; 
  unsigned char* key_buf;
  key_len = element_length_in_bytes(k) < 17 ? 17 : element_length_in_bytes(k);
  key_buf = (unsigned char*) malloc(key_len);
  element_to_bytes(key_buf, k);

  if( enc )
    AES_set_encrypt_key(key_buf + 1, 128, key);
  else
    AES_set_decrypt_key(key_buf + 1, 128, key);
  free(key_buf);

  memset(iv, 0, 16);
}

GByteArray*
aes_128_cbc_encrypt( GByteArray* pt, element_t k )
{
  AES_KEY key;
  unsigned char iv[16];
  GByteArray* ct;
  guint8 len[4];
  guint8 zero;

  init_aes(k, 1, &key, iv);

  /* TODO make less crufty */

  /* stuff in real length (big endian) before padding */
  len[0] = (pt->len & 0xff000000)>>24;
  len[1] = (pt->len & 0xff0000)>>16;
  len[2] = (pt->len & 0xff00)>>8;
  len[3] = (pt->len & 0xff)>>0;
  g_byte_array_prepend(pt, len, 4);

  /* pad out to multiple of 128 bit (16 byte) blocks */
  zero = 0;
  while( pt->len % 16 )
    g_byte_array_append(pt, &zero, 1);

  ct = g_byte_array_new();
  g_byte_array_set_size(ct, pt->len);

  AES_cbc_encrypt(pt->data, ct->data, pt->len, &key, iv, AES_ENCRYPT);

  return ct;
}

GByteArray*
aes_128_cbc_decrypt( GByteArray* ct, element_t k )
{
  AES_KEY key;
  unsigned char iv[16];
  GByteArray* pt;
  unsigned int len;
  
  init_aes(k, 0, &key, iv);

  pt = g_byte_array_new();
  g_byte_array_set_size(pt, ct->len);

  AES_cbc_encrypt(ct->data, pt->data, ct->len, &key, iv, AES_DECRYPT);
  
  /* TODO make less crufty */
  
  /* get real length */
  len = 0;
  len = len
    | ((pt->data[0])<<24) | ((pt->data[1])<<16)
    | ((pt->data[2])<<8)  | ((pt->data[3])<<0);

  g_byte_array_remove_index(pt, 0);

  g_byte_array_remove_index(pt, 0);

  g_byte_array_remove_index(pt, 0);

  g_byte_array_remove_index(pt, 0);

  return pt;
}

FILE*
fopen_read_or_die( char* file )
{
	FILE* f;

	if( !(f = fopen(file, "rb")) )
		die("can't read file: %s\n", file);

	return f;
}

FILE*
fopen_write_or_die( char* file )
{
	FILE* f;

	if( !(f = fopen(file, "wb")) )
		die("can't write file: %s\n", file);

	return f;
}

GByteArray*
suck_file( char* file )
{
	FILE* f;
	GByteArray* a;
	struct stat s;

	a = g_byte_array_new();
	stat(file, &s);
	g_byte_array_set_size(a, s.st_size);

	f = fopen_read_or_die(file);
	fread(a->data, 1, s.st_size, f);
	fclose(f);

	return a;
}

char*
suck_file_str( char* file )
{
	GByteArray* a;
	char* s;
	unsigned char zero;

	a = suck_file(file);
	zero = 0;
	g_byte_array_append(a, &zero, 1);
	s = (char*) a->data;
	g_byte_array_free(a, 0);

	return s;
}

char*
suck_stdin()
{
	GString* s;
	char* r;
	int c;

	s = g_string_new("");
	while( (c = fgetc(stdin)) != EOF )
		g_string_append_c(s, c);

	r = s->str;
	g_string_free(s, 0);

	return r;
}

void
spit_file( char* file, GByteArray* b, int free )
{
	FILE* f;

	f = fopen_write_or_die(file);
	fwrite(b->data, 1, b->len, f);
	fclose(f);

	if( free )
		g_byte_array_free(b, 1);
}

void read_cpabe_file( char* file,    GByteArray** cph_buf, int* file_len, GByteArray** aes_buf )
{
	FILE* f;
	int i;
	int len;

	*cph_buf = g_byte_array_new();
	*aes_buf = g_byte_array_new();

	f = fopen_read_or_die(file);

	/* read real file len as 32-bit big endian int */
	*file_len = 0;
	for( i = 3; i >= 0; i-- )
		*file_len |= fgetc(f)<<(i*8);

	/* read aes buf */
	len = 0;
	for( i = 3; i >= 0; i-- )
		len |= fgetc(f)<<(i*8);
	g_byte_array_set_size(*aes_buf, len);
	fread((*aes_buf)->data, 1, len, f);

	/* read cph buf */
	len = 0;
	for( i = 3; i >= 0; i-- )
		len |= fgetc(f)<<(i*8);
	g_byte_array_set_size(*cph_buf, len);
	fread((*cph_buf)->data, 1, len, f);
	
	fclose(f);
}

void
write_cpabe_file( char* file,   GByteArray* cph_buf, int file_len, GByteArray* aes_buf )
{
	FILE* f;
	int i;

	f = fopen_write_or_die(file);

	/* write real file len as 32-bit big endian int */
	for( i = 3; i >= 0; i-- )
		fputc((file_len & 0xff<<(i*8))>>(i*8), f);

	/* write aes_buf */
	for( i = 3; i >= 0; i-- )
		fputc((aes_buf->len & 0xff<<(i*8))>>(i*8), f);
	fwrite(aes_buf->data, 1, aes_buf->len, f);

	/* write cph_buf */
	for( i = 3; i >= 0; i-- )
		fputc((cph_buf->len & 0xff<<(i*8))>>(i*8), f);
	fwrite(cph_buf->data, 1, cph_buf->len, f);

	fclose(f);
}

void
die(char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
	exit(1);
}

/* To parse hidden attributes from input file */
void arsanvkabe_parse_attribute( GSList** l, char* a )
{
	/* We remove any leading or trailing space as it might impact the result of the hash function used*/
	a = g_strstrip(a);
	
	if( !strchr(a, '=') ) /* No yet supporting numerical attribute */
	{	
		*l = g_slist_append(*l, a);
	}	
	
	else
	{
		// do not add such attribute
		die("Only Non Numerical attributes are supported at the moment ! \n Non-numerical\n"
		"attributes are simply any string of letters, digits, and underscores\n"
		"beginning with a letter or a digit or any other character. If your attribute\n" 
		"starts with a special character such as *&^%^-_arthurMartins, you need to quote\n"
		"your attribute( \"*&^%^-_arthurMartins\") to avoid confusing the system interpreter.\n");
	}
}

/* To write a GByteArray into file */ 
void store_gbyte_array( GByteArray* b, const char *filename)
{
	FILE *file_descriptor = fopen(filename, "wb");
	//
	if (!file_descriptor)
	{
		g_error("Failed to open file %s \n", filename);
		return;
	}
	
	fwrite(b->data, 1, b->len, file_descriptor);
	fclose(file_descriptor);
}

/* To read a GByteArray from a file */ 
GByteArray *load_gbyte_array(const char *filename)
{
	FILE *file_descriptor = fopen(filename, "rb");
	if (!file_descriptor)
	{
		g_error("Failed to open file %s \n", filename);
		return NULL;
	}
	
	/* set index to get the size of data */
	fseek(file_descriptor, 0, SEEK_END);
	long file_size = ftell(file_descriptor);
	fseek(file_descriptor, 0, SEEK_SET);

	GByteArray *b = g_byte_array_new();
	g_byte_array_set_size(b, file_size);
	size_t bytes_read = fread(b->data, 1, file_size, file_descriptor);

	if (bytes_read != file_size)
	{
		g_warning("Failed to read entire file \n");
		
		g_byte_array_free(b, TRUE);
		fclose(file_descriptor);
		return NULL;
	}
	fclose(file_descriptor);

	return b;
}
