/*
Programmer: Gideon Walker 12450191
Class: CS 3800 Computer Security
Assignment: Final Project - Implementing Authentication and
  Confidentiality Services in OpenPGP
Date: 12/15/17
*/

#include <stdio.h>
#include <gmp.h>
#include <algorithm>
#include <string>
#include <iostream>
#include <vector>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <inttypes.h>
#include <string.h>
#include <fstream>
using namespace std;

const bool DEBUG = false;

RSA* generate_key(string key_fn){
  int ret = 0;
  RSA *r = NULL;
  BIGNUM *bne = NULL;
  BIO *bp_file = NULL;

  int bits = 2048;
  unsigned long e = RSA_F4;
  FILE * key_file = NULL;
  char * bignum_dec = NULL;

  // Make a new RSA key
  bne = BN_new();
  ret = BN_set_word(bne,e);
  if(ret != 1){
      goto free_all;
  }

  r = RSA_new();
  ret = RSA_generate_key_ex(r, bits, bne, NULL);
  if(ret != 1){
      goto free_all;
  }

  // Write out the public key
  bp_file = BIO_new_file(key_fn.c_str(), "w+");
  ret = PEM_write_bio_RSAPublicKey(bp_file, r);
  if(ret != 1){
      goto free_all;
  }

  // write out the prime number n
  key_file = fopen(key_fn.c_str(), "a");
  if(key_file == NULL){
    perror("Erorr opening file.");
    goto free_all;
  }
  else{
    fprintf(key_file, "n = %d\n", e);
  }

  // Write out the private key.
  ret = PEM_write_bio_RSAPrivateKey(bp_file, r, NULL, NULL, 0, NULL, NULL);

  // Free pointers
free_all:
  BIO_free_all(bp_file);
  BN_free(bne);
  fclose(key_file);

  return r;
}

// Returns a readable hex version of encrytped/hashed char*
string get_string(unsigned char * stuff){
  char mdString[SHA512_DIGEST_LENGTH*2+1];
  for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
      sprintf(&mdString[i*2], "%02x", (unsigned int)stuff[i]);
  return mdString;
}

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
  string signiture_str;
  string digest_str;
  string decrypted_str;
  string err;
  RSA* alice_keys = generate_key(alice_keys_fn);
  RSA* bob_keys = generate_key(bob_keys_fn);

  // Get file names
  if(! DEBUG){
    cout << "Enter the name of the file that contains "
         << "Alice’s public-private key pair:" << endl;
    cin >> alice_keys_fn;
    cout << "Enter the name of the file that contains "
         << "Bob’s public-private key pair:" << endl;
    cin >> bob_keys_fn;
    cout << "Enter the name of the file that contains "
         << "Alice’s plaintext message:" << endl;
    cin >> alice_text_fn;
    cout << "Enter the output file name to store Alice’s "
         << "authenticated message:" << endl;
    cin >> alice_auth_fn;
    cout << "Enter the output file name to store the verification "
         << "steps performed by Bob:" << endl;
    cin >> bob_verify_fn;
    cout << "Enter the output file name to store Alice’s "
         << "encrypted message:" << endl;
    cin >> alice_encrypt_fn;
    cout << "Enter the output file name to store Bob’s decryption "
         << "of Alice’s plaintext message:" << endl;
    cin >> bob_decrypt_fn;
    cout << endl;
  }

  //----------------
  // MESSAGE DIGEST
  //----------------
  // Grab the contents of the plaintext message from the file
  ifstream plaintext_f(alice_text_fn);
  string plaintext;
  string file_input;
  if(plaintext_f){
    while(getline(plaintext_f, file_input)){
      plaintext.append(file_input);
      // Getline does not include the new line char
      plaintext.append("\n");
    }
  }
  else cout << "Error opening " << alice_text_fn << endl;
  plaintext_f.close();
  if(DEBUG) cout << "Plaintext:" << endl << plaintext << endl;

  // Create a message digest by hashing with SHA512
  unsigned char digest[SHA512_DIGEST_LENGTH];
  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, plaintext.c_str(), plaintext.size());
  SHA512_Final(digest, &ctx);
  digest_str = get_string(digest);
  if(DEBUG) cout << "The digest is: " << endl << digest_str << endl << endl;

  //----------------------
  // ALICE - RSA SIGNING OF DIGEST
  //----------------------
  unsigned char *signiture = NULL;
  unsigned int signiture_len = 0;
  signiture = (unsigned char *)malloc(RSA_size(alice_keys));
  if(signiture == NULL){
    if(DEBUG) cout << "Failure with malloc." << endl;
  }

  // Make a signiture from the message digest with Alice's private key
  signiture_len = RSA_private_encrypt(sizeof digest, digest, signiture,
                                      alice_keys, RSA_PKCS1_PADDING);
  signiture_str = get_string(signiture);
  if(DEBUG) cout << "Alice's signiture of message:\n" << signiture_str << "\n\n";

  // Output to file
  ofstream alice_auth(alice_auth_fn);
  if(alice_auth)
    alice_auth << plaintext << signiture_str << "\n";
  else
    cout << "Error opening " << alice_auth_fn << "\n";
  alice_auth.close();

  //-----------------
  // BOB - VERIFY SIGNITURE
  //-----------------
  unsigned char *decrypted = NULL;
  unsigned int decrypted_len = 0;
  decrypted = (unsigned char *)malloc(RSA_size(alice_keys));

  // Decrypte the signiture w/ Alice's public key
  decrypted_len = RSA_public_decrypt(signiture_len, signiture, decrypted,
                                     alice_keys, RSA_PKCS1_PADDING);
  decrypted_str = get_string(decrypted);
  if(DEBUG) cout << "Heres the decrypted string:\n"<< decrypted_str << "\n";
  if(DEBUG){
    if(decrypted_str == digest_str) cout << "The strings match!" << "\n\n";
    else cout << ":( the strings do not match." << "\n\n";
  }

  // Output to file
  ofstream bob_verify(bob_verify_fn);
  if(bob_verify){
    bob_verify << "Digest line 2, Decrypted line 3:\n"
               << digest_str << "\n" << decrypted_str << "\n";
  }
  else
    cout << "Problem opening " << bob_verify_fn << "\n";
  bob_verify.close();

  //----------------------
  // ALICE - SEND ENCRYPTED SESSION KEY AND ENCRYPTED MESSAGE
  //----------------------
  uint8_t key[32];
  uint8_t initial_vector[AES_BLOCK_SIZE];
  RAND_bytes(key, sizeof(key));
  RAND_bytes(initial_vector, sizeof(initial_vector));
  unsigned char *key_char = (unsigned char *)key;
  string key_char_str = get_string(key_char);
  if(DEBUG) cout << "Session Key:\n" << key_char_str << "\n\n";

  // Encrypt the session key with Bob's public key
  signiture_len = RSA_public_encrypt(64, key_char, signiture, bob_keys,
                                     RSA_PKCS1_PADDING);
  signiture_str = get_string(signiture);
  if(DEBUG) cout << "Encrypted session key:\n" << signiture_str << "\n\n";

  // A copy of the initialization vector is needed since it is destroyed
  uint8_t initial_vector2[AES_BLOCK_SIZE];
  for(int i=0; i < AES_BLOCK_SIZE; i++){
  	initial_vector2[i] = initial_vector[i];
  }

  AES_KEY* aes_key = new AES_KEY();
  AES_set_encrypt_key(key, 256, aes_key);

  // The input needs to be padded.
  int padding = (AES_BLOCK_SIZE - (plaintext.length() % AES_BLOCK_SIZE));
  vector<unsigned char> padded_text(plaintext.begin(), plaintext.end());
  for(int i=0; i < padding; i++){
  	padded_text.push_back(0);
  }

  // Encryption function requires unsinged char *
  unsigned char * padded_text_char = &padded_text[0];
  const int padded_text_size = (const int)padded_text.size();

  unsigned char encrypted_data[512] = {0};
  AES_cbc_encrypt(padded_text_char, encrypted_data, padded_text_size,
                  (const AES_KEY*)aes_key, initial_vector, AES_ENCRYPT);
  string encrypted_str = get_string(encrypted_data);
  cout << "Encrypted data:\n" << encrypted_str << "\n\n";

  //---------------
  // BOB - RECIEVE SESSION KEY AND DECRYPT MESSAGE
  //---------------
  AES_KEY* aes_decrypt_key = new AES_KEY();
  AES_set_decrypt_key(key, 256, aes_decrypt_key);

  // Decrypt the session key that Alice sent
  decrypted_len = RSA_private_decrypt(signiture_len, signiture, decrypted,
                                      bob_keys, RSA_PKCS1_PADDING);
  decrypted_str = get_string(decrypted);
  if(DEBUG) cout << "Decrypted session key:" << endl << decrypted_str << endl;
  if(DEBUG){
    string msg;
    decrypted_str == key_char_str ? msg="Same Key!" : msg="Different key...";
    cout << msg << "\n\n";
  }

  // Decrypt the encrypted data
  unsigned char decrypted_data[512] = {0};
  AES_cbc_encrypt(encrypted_data, decrypted_data, padded_text_size,
                  (const AES_KEY*)aes_decrypt_key, initial_vector2, AES_DECRYPT);
  if(DEBUG){
    cout << "Decrypted message:" << endl;
    for(int i = 0; i<512; i++){
      printf("%c", decrypted_data[i]);
    }
    printf("\n");
  }

  // Output to file
  FILE *bob_decrypt;
  bob_decrypt = fopen(bob_decrypt_fn.c_str(), "w+");
  for(int i = 0; i<plaintext.size(); i++){
    fprintf(bob_decrypt, "%c", decrypted_data[i]);
  }
  fprintf(bob_decrypt, "\n");
  fclose(bob_decrypt);

  // free up the pointers
  RSA_free(alice_keys);
  RSA_free(bob_keys);
  delete signiture;
  delete decrypted;
  return 0;
}
