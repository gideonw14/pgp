#include <stdio.h>
#include <gmp.h>
#include <string>
#include <iostream>
#include <vector>
#include <openssl/sha.h>
#include <string.h>
#include <fstream>
using namespace std;

int main (){
  int num = 12;
  //fn stands for file name
  string alice_keys_fn;
  string bob_keys_fn;
  string alice_text_fn;
  string alice_auth_fn;
  string bob_verify_fn;
  string alice_encrypt_fn;
  string bob_decrypt_fn;
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
  ifstream plaintext_f("example_plaintext.txt");
  string plaintext;
  string file_input;
  if(plaintext_f){
    while(getline(plaintext_f, file_input)){
      plaintext.append(file_input);
    }
  }
  plaintext_f.close();
  plaintext.append("\n");
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

  printf("SHA512 digest: %s\n", mdString);

  return 0;
}
