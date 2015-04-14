/* Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */


#ifdef STANDARD
/* STANDARD is defined, don't use any mysql functions */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef __WIN__
typedef unsigned __int64 ulonglong;	/* Microsofts 64 bit types */
typedef __int64 longlong;
#else
typedef unsigned long long ulonglong;
typedef long long longlong;
#endif /*__WIN__*/
#else
#include <my_global.h>
#include <my_sys.h>
#if defined(MYSQL_SERVER)
#include <m_string.h>		/* To get strmov() */
#else
/* when compiled as standalone */
#include <string.h>
#define strmov(a,b) stpcpy(a,b)
#define bzero(a,b) memset(a,0,b)
#endif
#endif
#include <mysql.h>
//#include <ctype.h>

#ifdef HAVE_DLOPEN

#include <mcrypt.h>
#define STRBUF 64

my_bool aes_encrypt256_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
void aes_encrypt256_deinit(UDF_INIT *initid);
char *aes_encrypt256(UDF_INIT *initid, UDF_ARGS *args, char *result,
		unsigned long *length, char *null_value, char *error);

my_bool aes_decrypt256_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
void aes_decrypt256_deinit(UDF_INIT *initid);
char *aes_decrypt256(UDF_INIT *initid, UDF_ARGS *args, char *result,
		unsigned long *length, char *null_value, char *error);

/* Encrypt */
my_bool aes_encrypt256_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
	if(args->arg_count != 2) {
		strcpy(message,"Wrong number of arguments: aes_decrypt256 requires two arguments");
		return 1;
	}
	unsigned char *tmp;
	tmp = (char *)malloc(sizeof(char)*STRBUF);

	initid->maybe_null = 1;
	initid->max_length=STRBUF;
	initid->ptr = tmp;

	return 0;
}

void aes_encrypt256_deinit(UDF_INIT *initid __attribute__((unused)))
{
	free(initid->ptr);
}

char *aes_encrypt256(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args,
		char *result, unsigned long *length, char *null_value,
		char *error __attribute__((unused)))
{
	MCRYPT td;
	unsigned char *tmp = initid->ptr;
	int max_keylen, exp_len;
	char pad_len;

	if(!args->args[0] || !args->args[1]) {
		*null_value = 1;
		return 0;
	}
	if(args->lengths[0] >= STRBUF) {
		*null_value = 1;
		return 0;
	}
	if(args->lengths[1] > 32) {
		*null_value = 1;
		return 0;
	}

	td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, NULL, MCRYPT_ECB, NULL);
	if(td == MCRYPT_FAILED) {
		*null_value = 1;
		return 0;
	}

	max_keylen = mcrypt_enc_get_key_size(td);

	if(args->lengths[1] > max_keylen) {
		*null_value = 1;
		return 0;
	}

	if(mcrypt_generic_init(td, args->args[1], max_keylen, 0) < 0) {
		*null_value = 1;
		return 0;
	}

	exp_len = 16 * ((int)(args->lengths[0] / 16) + 1);
	pad_len = exp_len - args->lengths[0];

	memset(tmp, 0x0, STRBUF);
	memcpy(tmp, args->args[0], args->lengths[0]);
	memset(tmp+exp_len-pad_len, pad_len, (int)pad_len);

	if(mcrypt_generic(td, tmp, exp_len)) {
		*null_value = 1;
		mcrypt_generic_deinit(td);
		mcrypt_module_close(td);

		return 0;
	}

	mcrypt_generic_deinit(td);
	mcrypt_module_close(td);

	result = tmp;
	*length = (uint)strlen(result);

	*null_value = 0;
	return result;
}

/* Decrypt */

my_bool aes_decrypt256_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
	if(args->arg_count != 2) {
		strcpy(message,"Wrong number of arguments: aes_decrypt256 requires two arguments");
		return 1;
	}

	unsigned char *tmp;
	tmp = (char *)malloc(sizeof(char)*STRBUF);

	initid->maybe_null=1;
	initid->max_length=STRBUF;
	initid->ptr = tmp;

	return 0;
}

void aes_decrypt256_deinit(UDF_INIT *initid __attribute__((unused)))
{
	free(initid->ptr);
}

char *aes_decrypt256(UDF_INIT *initid __attribute__((unused)), UDF_ARGS *args,
		char *result, unsigned long *length, char *null_value,
		char *error __attribute__((unused)))
{
	MCRYPT td;
	unsigned char *tmp = initid->ptr;
	int max_keylen, sz;
	char last;

	if(!args->args[0] || !args->args[1]) {
		*null_value = 1;
		return 0;
	}
	if(args->lengths[0]/16 == 0) {
		*null_value = 1;
		return 0;
	}
	if(args->lengths[0] >= STRBUF) {
		*null_value = 1;
		return 0;
	}

	td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, NULL, MCRYPT_ECB, NULL);
	if(td == MCRYPT_FAILED) {
		*null_value = 1;
		return 0;
	}

	max_keylen = mcrypt_enc_get_key_size(td);

	if(args->lengths[1] > max_keylen) {
		*null_value = 1;
		return 0;
	}

	if(mcrypt_generic_init(td, args->args[1], max_keylen, 0) < 0) {
		*null_value = 1;
		return 0;
	}

	memset(tmp, 0x0, STRBUF);
	memcpy(tmp, args->args[0], args->lengths[0]);

	if(mdecrypt_generic(td, tmp, args->lengths[0])) {
		*null_value = 1;
		mcrypt_generic_deinit(td);
		mcrypt_module_close(td);

		return 0;
	}
	mcrypt_generic_deinit(td);
	mcrypt_module_close(td);

	last = tmp[strlen(tmp) - 1];
	if(last > 16) {
		*null_value = 1;
		return 0;
	}
	*length = strlen(tmp) - last;
	strncpy(result, tmp, *length);
	result[*length] = 0;

	*null_value = 0;
	return result;
}

#endif /* HAVE DLOPEN */
