#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/x509.h"

// base64反解
int base64_decode(char *src,unsigned char *dst)
{
    char *q=malloc(strlen(src)+1);
    char *p=dst;
    char *temp=q;
    char *s=src;
    int len=strlen(src),i;
    memset(q,0,strlen(src)+1);
    while(*s)
    {
        if(*s>='A'&&*s<='Z') *temp=*s-'A';
        else if(*s>='a'&&*s<='z') *temp=*s-'a'+26;
        else if(*s>='0'&&*s<='9') *temp=*s-'0'+52;
        else if(*s=='+') *temp=62;
        else if(*s=='/') *temp=63;
        else if(*s=='=') *temp=-1;
        else
        {
            return 1;
        }
        ++s;
        ++temp;
    }
    for(i=0;i<len-4;i+=4)
    {
        *p++=(*(q+i)<<2)+(*(q+i+1)>>4);
        *p++=(*(q+i+1)<<4)+(*(q+i+2)>>2);
        *p++=(*(q+i+2)<<6)+(*(q+i+3));
    }
    if(*(q+i+3)!=-1)
    {
        *p++=(*(q+i)<<2)+(*(q+i+1)>>4);
        *p++=(*(q+i+1)<<4)+(*(q+i+2)>>2);
        *p++=(*(q+i+2)<<6)+*(q+i+3);
    }
    else if(*(q+i+2)!=-1)
    {
        *p++=(*(q+i)<<2)+(*(q+i+1)>>4);
        *p++=(*(q+i+1)<<4)+(*(q+i+2)>>2);
        *p++=(*(q+i+2)<<6);
    }
    else if(*(q+i+1)!=-1)
    {
        *p++=(*(q+i)<<2)+(*(q+i+1)>>4);
        *p++=(*(q+i+1)<<4);
    }
    else
    {
        return 1;
    }
    *p=0;
    free(q);
    
    return 0;
}

// RSA解密
int DoPublicKeyDecryption(const unsigned char *key,int key_size,const unsigned char *from,int from_size,unsigned char *to,int to_size)
{
	int						padding;
	int						fsurlen,to_count,flen;
	int						result;
	int						i;
	const unsigned char	*ucp;
	unsigned char			*from_temp;
	unsigned char			*to_temp;
	RSA						*rsa;
    
	ucp = key;
	rsa = d2i_RSA_PUBKEY(NULL, &ucp, key_size);
	if(NULL == rsa)
	{
        return 0;
	}
    
	padding = RSA_PKCS1_PADDING;
	flen = RSA_size(rsa);
    
	from_temp = (unsigned char*)malloc(flen);
	to_temp = (unsigned char*)malloc(flen);
	fsurlen = from_size;
	to_count = 0;
    
	for(i = 0; fsurlen > 0; i++)
	{
		memset(from_temp, 0x00, flen);
		memset(to_temp, 0x00, flen);
		memcpy(from_temp, &from[flen * i], flen);
		fsurlen -= flen;
		result = RSA_public_decrypt(flen, from_temp, to_temp, rsa, padding);
		if(-1 == result)
		{
			free(rsa);
			free(from_temp);
			free(to_temp);
			return 0;
		}
        
		memcpy(to + to_count, to_temp,result);
		to_count += result;
		if((to_count + result) > to_size)
		{
			free(rsa);
			free(from_temp);
			free(to_temp);
			return 0;
		}
	}
	
	free(rsa);
	free(from_temp);
	free(to_temp);
	return to_count;
}

// 公共Key
char* RSAPublicDecrypt(char *publickey, char *dem)
{
    //base64解码  key
    int lenKey = ((strlen(publickey)+2)*4/3)+1;
    unsigned char *puk = (unsigned char *)malloc(lenKey);
    memset(puk, 0x00, lenKey);
    if (base64_decode(publickey, puk) != 0)
    {
        return "";
    }
    
    //printf("depuk lenght: %lu\n",strlen(puk));
    
    //反base64解码  密文
    int lenDem = ((strlen(dem)+2)*4/3)+1;
    unsigned char *de = (unsigned char *)malloc(lenDem);
    memset(de, 0x00, lenDem);
    if (base64_decode(dem, de) != 0)
    {
        return "";
    }
    
    //printf("depuk lenght: %lu\n",strlen(de));
    
    //解密
    unsigned int lenPlaintext = lenKey-11 + 1; //明文长度 <= 密钥长度 - 11
    unsigned char *plaintext = (unsigned char *)malloc(lenPlaintext);
    unsigned int txtlen;
    memset(plaintext, 0x00, lenPlaintext);
    txtlen = DoPublicKeyDecryption(puk, lenKey, de, lenDem, plaintext, lenPlaintext);
    
    free(puk);
    free(de);
    free(plaintext);
    
    return plaintext;
}
/*
int main()
{
	char *depuk =  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC2kcrRvxURhFijDoPpqZ/IgPlAgppkKrek6wSrua1zBiGTwHI2f+YCa5vC1JEiIi9uw4srS0OSCB6kY3bP2DGJagBoEgj/rYAGjtYJxJrEiTxVs5/GfPuQBYmU0XAtPXFzciZy446VPJLHMPnmTALmIOR5Dddd1Zklod9IQBMjjwIDAQAB";
    char *dem = "YFSGlJTpNYakrZuZqZ55dcA5mVUb/JQBr3hdDjODsAVSdoVVytIagk9Wt0CD/uX+7jGL9pqev8/u0I0ZBKEmz5huXp8TdZSnskCZ7GTeHNW0VPJcW8OcBxAValA0jQSv2mBP+tc1r6mdvf66GEzhvgBfTnp3Sp7V3dijJ9bNstIDyrGm/BlByhcMr3UqXjTFJaui6t5TxvZhCuSV9sg+xVVA+sR3uFI78b5lKomg5Vu31EBZvXASlFfaOc4StltRUH2aSiRqjnbXe8dlRZO0Ih44htYs2QfehzeQnPHtTwNHUvtVIVcIdI/7j9yfy5es13QeIgfKghY/ENUnB2V7iA==";
    
    char *plaintext = RSAPublicDecrypt(depuk, dem);
    
    printf("Plaintext: %s\n", plaintext);
    
	return 1;
}*/
