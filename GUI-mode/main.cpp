#include <stdio.h>
#include <iostream>
#include <string>
#include <randpool.h>
#include <rsa.h>
#include <hex.h>
#include <aes.h>
#include <des.h>
#include <md5.h>
#include <files.h>
#pragma comment( lib, "cryptlib.lib" )
using namespace std; 
using namespace CryptoPP;

void myDES(FILE *fin,FILE *fout,bool type); //DES算法
string Hash(char path[],char hash[]); //MD5算法
void mySign(char path[],FILE *fin,FILE *fout,bool type); //数字签名
//--------rsa的函数-----------//
void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed);
string RSAEncryptString(const char *pubFilename, const char *seed, const string message);
string RSADecryptString(const char *privFilename, const string ciphertext);
RandomPool & GlobalRNG()
{	static RandomPool randomPool;
	return randomPool;
}
//--------rsa的函数-----------//
void putkey(FILE *fin,FILE *fout,bool type); //数字信封+数字签名(加密秘钥)

int main(int argc,char *argv[])
{	string option=argv[1];
	FILE *fin,*fout;
	fin = fopen(argv[2],"rb");
	
	if(option=="des1") //des加密
	{	fout = fopen(argv[3],"wb");
		myDES(fin,fout,1);
		cout<<"成功！";
	}
	else if(option=="des0") //des解密
	{	fout = fopen(argv[3],"wb");
		myDES(fin,fout,0);
		cout<<"成功！";
	}
	else if(option=="md5a") //计算hash
	{	fout = fopen(argv[3],"wb");
		char hash[33]={'\0'};
		Hash(argv[2],hash);
		fwrite(hash,32,1,fout);
		cout<<hash<<endl;  
	}
	else if(option=="md5b") //比较hash
	{	char ahash[33]={'\0'},bhash[33]={'\0'};
		fout = fopen(argv[3],"rb");
		fread(ahash,32,1,fin);
		fread(bhash,32,1,fout);
		cout<<ahash<<" "<<bhash<<endl;
		if(string(ahash)!=string(bhash)) cout<<"摘要不一致！";
		else cout<<"摘要一致！";
	}
	else if(option=="sign1")
	{	fout = fopen(argv[3],"wb");
		mySign(argv[2],fin,fout,1);
	}
	else if(option=="sign0")
	{	fout = fopen(argv[3],"wb");
		mySign(argv[3],fin,fout,0);
	}
	else if(option=="alluse1")
	{	fout = fopen(argv[3],"wb");
		mySign(argv[2],fin,fout,1);
		fclose(fout);fclose(fin);
		fout=fopen(argv[3],"rb");
		fin =fopen(argv[2],"wb");
		myDES(fout,fin,1);
		putkey(fin,fout,1);
		cout<<argv[2]<<"已加密\n";
		cout<<"加密后的公钥存入key.txt\n";
	}
	else if(option=="alluse0")
	{	fout = fopen(argv[3],"wb");
		putkey(fin,fout,0);
		myDES(fin,fout,0);
		fclose(fout);fclose(fin);
		fout=fopen(argv[3],"rb");
		fin =fopen(argv[2],"wb");
		mySign(argv[2],fout,fin,0);
		cout<<argv[2]<<"已解密\n";
		cout<<"解密后的公钥存入key.txt\n";
	}
	else
		cout<<"无效的输入";
	fclose(fin);
	fclose(fout);
	return 0;
}
//DES
void myDES(FILE *fin,FILE *fout,bool type) //DES
{	unsigned char key[8]={89,146,116,197,155,228,172,93};
    unsigned char input[8];
    unsigned char output[8];
	
	if(type) //加密
	{	bool NotEnd;
		DESEncryption encryption_DES;
		encryption_DES.SetKey(key,8);
		do
		{	memset(input,'\0',8);
			NotEnd = fread(&input,8,1,fin);
			encryption_DES.ProcessBlock( input, output );
			fwrite(output,8,1,fout);
		}while(NotEnd);
	}
	else //解密
	{	DESDecryption decryption_DES;    
		decryption_DES.SetKey(key,8);
		while(fread(&input,8,1,fin))
		{	decryption_DES.ProcessBlock(input,output);
			fwrite(output,8,1,fout);
		}
	}
}

string Hash(char path[],char hash[])  //完整性检测
{	CryptoPP::MD5 md;
	const size_t size = CryptoPP::MD5::DIGESTSIZE * 2;
	byte buf[size] = {0};
	string strPath = string(path);
	CryptoPP::FileSource(strPath.c_str(), true, new CryptoPP::HashFilter(md, new CryptoPP::HexEncoder( new CryptoPP::ArraySink(buf, size))));
	string strHash = string(reinterpret_cast<const char*>(buf), size);
	strcpy(hash, strHash.c_str());
	return strHash;
}
//数字签名
void mySign(char path[],FILE *fin,FILE *fout,bool type) 
{	char hash[17]={'\0'},output[512]={'\0'},contain[1]={'\0'}; 
	string strhash = Hash(path,hash);
	RandomPool randPool;
    char priKey[] = "pri";
	char pubKey[] = "pub";
	char seed[] = "seed";
	
	if(type)    //发送方
	{	GenerateRSAKey(1024, priKey, pubKey, seed);
		cout<<"原摘要:   "<<strhash<<endl;
		string xxx = RSAEncryptString(pubKey, seed, strhash);  // RSA 加密
		cout << "加密摘要: " << xxx << endl <<endl;
		strcpy(output, xxx.c_str());
		fwrite(output,xxx.length(),1,fout);
		while(fread(contain,1,1,fin)) fwrite(contain,1,1,fout);
	}
	else       //接收方
	{	char xxx[512]={'\0'};
		fread(xxx,256,1,fin);
		while(fread(contain,1,1,fin)) fwrite(contain,1,1,fout);
		fclose(fout);
		string strhash = Hash(path,hash);
		string newhash = RSADecryptString(priKey, string(xxx));  // RSA 解密
		cout<<"摘要对比:\t"<<newhash<<"\n\t\t"<<strhash<< endl;
		fout=fopen(path,"rb");
	}
}
//rsa获取秘钥
void GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename, const char *seed)
{	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, strlen(seed));
	RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
	HexEncoder privFile(new FileSink(privFilename));
	priv.AccessMaterial().Save(privFile);
	privFile.MessageEnd();
	RSAES_OAEP_SHA_Encryptor pub(priv);
	HexEncoder pubFile(new FileSink(pubFilename));
	pub.AccessMaterial().Save(pubFile);
	pubFile.MessageEnd();
}
//rsa加密
string RSAEncryptString(const char *pubFilename, const char *seed, const string message)
{	FileSource pubFile(pubFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Encryptor pub(pubFile);
	RandomPool randPool;
	randPool.IncorporateEntropy((byte *)seed, strlen(seed));
	std::string result;
	StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(new StringSink(result))));
	return result;
}
//rsa解密
string RSADecryptString(const char *privFilename, const string ciphertext)
{	FileSource privFile(privFilename, true, new HexDecoder);
	RSAES_OAEP_SHA_Decryptor priv(privFile);
	std::string result;
	StringSource(ciphertext, true, new HexDecoder(new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));
	return result;
}

void putkey(FILE *fin,FILE *fout,bool type)
{	RandomPool randPool;
	char priKey[] = "pri";
	char pubKey[] = "pub";
	char seed[] = "seed";
	char output[512]={'\0'};
	if(type)
	{	FILE *fpr=fopen("key.txt","wb");
		unsigned char key[8]={89,146,116,197,155,228,172,93};
		string str = (char*)key;
		string xxx = RSAEncryptString(pubKey, seed, str);
		strcpy(output, xxx.c_str());
		fwrite(output,xxx.length(),1,fpr);
	}
	else
	{	FILE *fpr=fopen("key.txt","rb");
		fread(output,256,1,fpr);
		string str = RSADecryptString(priKey, string(output));
		strcpy(output, str.c_str());
		fclose(fpr);
		char key[128]={'\0'};
		strcpy(key, str.c_str());
		fpr=fopen("key.txt","wb");
		fwrite(key,str.length(),1,fpr);
	}
}
