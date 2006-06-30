/* This program changes the password of a .p12 file */
/* Author: James A. Rome                            */
/* June 28, 2006                                    */
/* This program is freely available for any use     */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

int main(int argc, char * argv[]) {
	char oldpw[257], newpw[257], newpw2[257];
	int err = 0;
	FILE *in_file, *out_file;
	PKCS12 *p12;
	EVP_PKEY *pkey;
	X509 *cert;
	STACK_OF(X509) *ca = NULL;
	
	if(argc < 2) {
		printf("Usage: change_p12_pwd infile.p12 outfile.p12\n");
		exit(1);
	}
	SSLeay_add_all_algorithms();
	ERR_load_crypto_strings();
	
	if(!(in_file = fopen(argv[1], "r"))) {
			fprintf(stderr, "Error reading PKCS#12 file\n");
		ERR_print_errors_fp(stderr);
		exit (1);
	}
	printf("Enter the old password for this p12 file: ");
	scanf("%256s", &oldpw);
	do {
		printf("Enter the new password for this p12 file: ");
		scanf("%256s", &newpw);
		printf("Reenter the new password for this p12 file: ");
		scanf("%256s", &newpw2);
	}
	while ( strncmp(newpw, newpw2, 256) != 0);
	/* We now have the new and old passwords and can change it */
	/* Make the p12 structure */
	p12 = d2i_PKCS12_fp(in_file, NULL);
	fclose (in_file);
	if (!p12) {
		fprintf(stderr, "Error reading PKCS#12 file\n");
		ERR_print_errors_fp(stderr);
		exit (1);
	}
	if (!PKCS12_parse(p12, oldpw, &pkey, &cert, &ca)) {
		fprintf(stderr, "Error parsing PKCS#12 file\n");
		ERR_print_errors_fp(stderr);
		exit (1);
	}
	if (!(PKCS12_newpass(p12, oldpw,newpw))) {
		fprintf(stderr, "Error changing password\n");
		ERR_print_errors_fp(stderr);
		exit (1);
	}
	if (!(out_file = fopen(argv[2], "wb"))) {
		fprintf(stderr, "Error opening file %s\n", argv[2]);
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	i2d_PKCS12_fp(out_file, p12);
	PKCS12_free(p12);
	fclose(out_file);

}
