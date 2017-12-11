#include <stdio.h>
#include <gmp.h>
#include <string>

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

  printf("Enter the name of the file that contains Alice’s public-private key pair:\n");
  scanf("%s\n", alice_keys_fn);
  printf("Enter the name of the file that contains Bob’s public-private key pair:\n");
  scanf("%s\n", );
  printf("Enter the name of the file that contains Alice’s plaintext message:\n");
  scanf("%s\n", );
  printf("Enter the output file name to store Alice’s authenticated message:\n");
  scanf("%s\n", );
  printf("Enter the output file name to store the verification steps performed by Bob:\n");
  scanf("%s\n", );
  printf("Enter the output file name to store Alice’s encrypted message:\n");
  scanf("%s\n", );
  printf("Enter the output file name to store Bob’s decryption of Alice’s plaintext message:\n");
  scanf("%s\n", );


  return 0;
}
