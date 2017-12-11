#include <stdio.h>
#include <gmp.h>
#include <string>
#include <iostream>
#include <vector>
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

  return 0;
}
