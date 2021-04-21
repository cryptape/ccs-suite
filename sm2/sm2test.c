#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sm2.h"

int sm2_set_public_key_x(SM2_KEY *key,const char public_key[64])
{
	int i;
	unsigned char t;
	for (i = 0; i < 64; i++)
	{
		t = 0;

		if(public_key[i]>='0' && public_key[i]<='9' ) t = public_key[i]-'0';
		else if(public_key[i]>='a' && public_key[i]<='f' ) t = public_key[i]-'a' + 0xa;
		else if(public_key[i]>='A' && public_key[i]<='F' ) t = public_key[i]-'A' + 0xa;
		
		t = t << 4;
		i++;

		if(public_key[i]>='0' && public_key[i]<='9' ) t = t | public_key[i]-'0';
		else if(public_key[i]>='a' && public_key[i]<='f' ) t = t | (public_key[i]-'a' + 0xa);
		else if(public_key[i]>='A' && public_key[i]<='F' ) t = t | (public_key[i]-'A' + 0xa);

		key->public_key.x[i>>1] = t;
	}
	return 1;	
}

int sm2_set_public_key_y(SM2_KEY *key,const char public_key[64])
{
	int i;
	unsigned char t;
	for (i = 0; i < 64; i++)
	{
		t = 0;

		if(public_key[i]>='0' && public_key[i]<='9' ) t = public_key[i]-'0';
		else if(public_key[i]>='a' && public_key[i]<='f' ) t = public_key[i]-'a' + 0xa;
		else if(public_key[i]>='A' && public_key[i]<='F' ) t = public_key[i]-'A' + 0xa;
		
		t = t << 4;
		i++;

		if(public_key[i]>='0' && public_key[i]<='9' ) t = t | public_key[i]-'0';
		else if(public_key[i]>='a' && public_key[i]<='f' ) t = t | (public_key[i]-'a' + 0xa);
		else if(public_key[i]>='A' && public_key[i]<='F' ) t = t | (public_key[i]-'A' + 0xa);

		key->public_key.y[i>>1] = t;
	}
	return 1;	
}

int sm2_set_signature_r(SM2_SIGNATURE *sig,const char signature_r[64])
{
	int i;
	unsigned char t;
	for (i = 0; i < 64; i++)
	{
		t = 0;
		if(signature_r[i]>='0' && signature_r[i]<='9' ) t = signature_r[i]-'0';
		else if(signature_r[i]>='a' && signature_r[i]<='f' ) t = signature_r[i]-'a' + 0xa;
		else if(signature_r[i]>='A' && signature_r[i]<='F' ) t = signature_r[i]-'A' + 0xa;
		
		t = t << 4;
		i++;

		if(signature_r[i]>='0' && signature_r[i]<='9' ) t = t | signature_r[i]-'0';
		else if(signature_r[i]>='a' && signature_r[i]<='f' ) t = t | (signature_r[i]-'a' + 0xa);
		else if(signature_r[i]>='A' && signature_r[i]<='F' ) t = t | (signature_r[i]-'A' + 0xa);

		sig->r[i>>1] = t;
	}	
	return 1;
}

int sm2_set_signature_s(SM2_SIGNATURE *sig,const char signature_s[64])
{
	int i;
	unsigned char t;
	for (i = 0; i < 64; i++)
	{
		t = 0;
		if(signature_s[i]>='0' && signature_s[i]<='9' ) t = signature_s[i]-'0';
		else if(signature_s[i]>='a' && signature_s[i]<='f' ) t = signature_s[i]-'a' + 0xa;
		else if(signature_s[i]>='A' && signature_s[i]<='F' ) t = signature_s[i]-'A' + 0xa;
		
		t = t << 4;
		i++;

		if(signature_s[i]>='0' && signature_s[i]<='9' ) t = t | signature_s[i]-'0';
		else if(signature_s[i]>='a' && signature_s[i]<='f' ) t = t | (signature_s[i]-'a' + 0xa);
		else if(signature_s[i]>='A' && signature_s[i]<='F' ) t = t | (signature_s[i]-'A' + 0xa);

		sig->s[i>>1] = t;
	}	
	return 1;
}
/*
private-key = 51018bc2dd749d8b37fd6a92fa4bf418e8acaa348d13c6dd3843d1965084469f
public-key = 80feac93555c3cb80afa81b64088af3896d0eaff99a70e0fc4777cacdac22caa b2a9812c577c642ac3b58eece4ca61d912bce1cbfa2f30c04d74b8ed367337c2
sig.r = 130c099c9953658fbe8f6211b38ab1dc2cbc7d1a256b39970d89dfbef17cea44
sig.s = 0ee7f776353a21193bb67d45159d8b9de0474009d3bc5e89f501f35008d24dec
verify2 success
*/

//B2E14C5C79C6DF5B85F4FE7ED8DB7A262B9DA7E07CCB0EA9F4747B8CCDA8A4F3
int set_dgst(unsigned char dgst[32],const char za[64] )
{
	int i;
	unsigned char t;
	for (i = 0; i < 64; i++)
	{
		t = 0;
		if(za[i]>='0' && za[i]<='9' ) t = za[i]-'0';
		else if(za[i]>='a' && za[i]<='f' ) t = za[i]-'a' + 0xa;
		else if(za[i]>='A' && za[i]<='F' ) t = za[i]-'A' + 0xa;
		
		t = t << 4;
		i++;

		if(za[i]>='0' && za[i]<='9' ) t = t | za[i]-'0';
		else if(za[i]>='a' && za[i]<='f' ) t = t | (za[i]-'a' + 0xa);
		else if(za[i]>='A' && za[i]<='F' ) t = t | (za[i]-'A' + 0xa);

		dgst[i>>1] = t;
	}		
}

int main(void)
{
	SM2_KEY key;
	SM2_SIGNATURE sig;
	unsigned char dgst[32] = {1, 2, 3};
	int r;

	sm2_set_public_key_x(&key,"09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020");
	sm2_set_public_key_y(&key,"CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13");
	//sm2_key_print(stdout, &key, 0, 0);

	sm2_set_signature_r(&sig,"F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3");
	sm2_set_signature_s(&sig,"B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA");
	//sm2_signature_print(stdout, &sig, 0, 0);

	set_dgst(dgst,"F0B43E94BA45ACCAACE692ED534382EB17E6AB5A19CE7B31F4486FDFC0D28640");


	int i=0;
	int sum=0;
	for(i=0;i<100;i++)
	{
			r = sm2_do_verify(&key, dgst, &sig);
			sum += (r > 0 ? 1 : 0);
	}
	//printf("verify2 %s\n", r > 0 ? "success" : "failed");

	return sum;
}
