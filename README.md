# pgp
Programmer: Gideon Walker 12450191
Class: CS 3800 Computer Security
Assignment: Final Project - Implementing Authentication and
  Confidentiality Services in OpenPGP
Date: 12/15/17

Purpose of files:
+ gwalker_pgp.cpp - runs main program
+ example_plaintext.txt - the example message input. NOTE: Program does not
generate message but rather reads it in from a file. Make sure to spell it
correctly or the program will fail.
+ Makefile - compiles the program. NOTE: make clean is available.

How to compile and run.
1. `make` or `g++ -std=c++11 gwalker_pgp.cpp -o program -lgmp -lcrypto`
2. `./program`
3. Generates the several files required for the assignment after inputing the
file names.
