MySQL user defined function which uses AES 256bit encrypt and decrypt
========

## Prerequired
* mysql development package (header files)
* libmcrypt
* gcc

## Build
-I stands for location where mysql header files at.

'''
shell> gcc -O2 -fPIC -shared -I/usr/include/mysql -lmcrypt -o aes256.so mysqludf_aes256_mcrypt.c
'''

## Install
move aes256.so file to mysql plugin directory. (ex /usr/lib64/mysql/plugin)

'''
mysql> CREATE FUNCTION aes256_encrypt RETURNS STRING SONAME 'aes256.so';
mysql> CREATE FUNCTION aes256_decrypt RETURNS STRING SONAME 'aes256.so';
'''

## Uninstall
'''
mysql> DROP FUNCTION aes256_encrypt;
mysql> DROP FUNCTION aes256_decrypt;
'''

remove aes256.so file.

## Usage
'''
mysql> SELECT aes256_encrypt('STRING TO ENCRYPT', 'KEY');
mysql> SELECT aes256_decrypt('STRING TO DECRYPT', 'KEY');
'''

## Author
Peter Jang <hsjang@gmail.com>
