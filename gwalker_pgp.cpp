#include <stdio.h>
#include <gmp.h>
#include <string>
#include <iostream>
#include <vector>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <string.h>
#include <fstream>
using namespace std;

const bool DEBUG = true;

int main (){
  int rc = 1;
  //fn stands for file name
  string alice_keys_fn = "alice_key.pem";
  string bob_keys_fn = "bob_key.pem";
  string alice_text_fn = "example_plaintext.txt";
  string alice_auth_fn = "alice_signed.txt";
  string bob_verify_fn = "bob_verify.txt";
  string alice_encrypt_fn = "alice_encrypt.txt";
  string bob_decrypt_fn = "bob_decrypt.txt";
  vector<string> inputs;
  /*
  cout << "Enter the name of the file that contains Alice’s public-private key pair:" << endl;
  cin >> alice_keys_fn;
  inputs.push_back(alice_keys_fn);
  cout << "Enter the name of the file that contains Bob’s public-private key pair:" << endl;
  cin >> bob_keys_fn;
  inputs.push_back(bob_keys_fn);
  cout << "Enter the name of the file that contains Alice’s plaintext message:" << endl;
  cin >> alice_text_fn;
  inputs.push_back(alice_text_fn);
  cout << " Enter the output file name to store Alice’s authenticated message:" << endl;
  cin >> alice_auth_fn;
  inputs.push_back(alice_auth_fn);
  cout << "Enter the output file name to store the verification steps performed by Bob:" << endl;
  cin >> bob_verify_fn;
  inputs.push_back(bob_verify_fn);
  cout << "Enter the output file name to store Alice’s encrypted message:" << endl;
  cin >> alice_encrypt_fn;
  inputs.push_back(alice_encrypt_fn);
  cout << "Enter the output file name to store Bob’s decryption of Alice’s plaintext message:" << endl;
  cin >> bob_decrypt_fn;
  inputs.push_back(bob_decrypt_fn);

  for(int i=0; i<inputs.size(); i++){
    cout << inputs[i] << " ";
  }
  cout << endl;
  */
  //----------------
  // MESSAGE DIGEST
  //----------------
  ifstream plaintext_f("example_plaintext.txt");
  string plaintext;
  string file_input;
  if(plaintext_f){
    while(getline(plaintext_f, file_input)){
      plaintext.append(file_input);
      // Getline does not include the new line char
      plaintext.append("\n");
    }
  }
  plaintext_f.close();

  cout << "plaintext:" << endl;
  cout << plaintext << endl;
  unsigned char digest[SHA512_DIGEST_LENGTH];

  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, plaintext.c_str(), plaintext.size());
  SHA512_Final(digest, &ctx);

  char mdString[SHA512_DIGEST_LENGTH*2+1];
  for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
      sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);

  if(DEBUG){printf("SHA512 digest: %s\n\n", mdString);}
  //----------------
  // RSA SIGNING OF DIGEST
  //----------------
  string alice_key;
  alice_keys_fn = "alice_key.pem";
  ifstream alice_file(alice_keys_fn);
  if(alice_file){
    while(getline(alice_file, file_input)){
      alice_key.append(file_input);
      alice_key.append("\n");
    }
  }
  if(DEBUG){cout << "Alice's Key:" << endl << alice_key << endl;}
  if(DEBUG){cout << "Length of " << alice_key.size() << endl;}
  BIO *bio = NULL;
  RSA *rsa = NULL;

  bio = BIO_new_mem_buf(alice_key.c_str(), alice_key.size());
  rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
  if(DEBUG){cout << "Alices's key read from PEM: " << endl << rsa << endl;}

  unsigned char *signiture = NULL;
  unsigned int signiture_len = 0;
  if(DEBUG){cout << "Rsa size " << RSA_size(rsa) << endl;}
  signiture = (unsigned char *)malloc(RSA_size(rsa));
  if(signiture == NULL){
    if(DEBUG){cout << "Failure with malloc." << endl;}
  }
  rc = RSA_sign(NID_sha512, digest, sizeof digest, signiture, &signiture_len, rsa);
  if(rc != 1){
    if(DEBUG){cout << "Failure with RSA_sign." << endl;}
  }
  if(DEBUG){
    cout << "Alices signiture is " << signiture << endl <<
    "With length " << sizeof signiture << endl;
  }

  ofstream output_file(alice_auth_fn);
  if(output_file){
    output_file << signiture;
    output_file << "\n";
  }
  output_file.close();
  if(rsa != NULL){
    RSA_free(rsa);
    rsa = NULL;
  }
  if(bio != NULL){
    BIO_free(bio);
    bio = NULL;
  }

  //-----------------
  // VERIFY SIGNITURE
  //-----------------

  bio = BIO_new_mem_buf(alice_key.c_str(), alice_key.size());
  FILE * file;
  file = fopen(alice_keys_fn.c_str(), "r");
  rsa = PEM_read_RSAPublicKey(file, NULL, NULL, NULL);
  fclose(file);
  if(DEBUG){cout << "Alice Public key is " << rsa << endl;}
  rc = RSA_verify(NID_sha512, digest, sizeof digest, signiture, signiture_len, rsa);
  if(rc != 1){
    if(DEBUG){cout << "Error verifying the signiture!" << endl;}
  }
  return 0;
}
