Cred Crypt 0.7.6
================

An extendable credential management utility intended to be portable simple and secure.
Written in C and C++.

Dependencies
------------
 * Google Test >= 1.2.0

Features
--------
 * C++ API
 * All credentials are encrypted when not being displayed
 * Clears all sensitive information from memory when no longer in use
 * MasterKey is removed from memory after 30 seconds of no activity

Specifications
--------------
 * SCRYPT: used for key stretching
 * Skein_512: used for hashing
 * Threefish_512_CTR: used to encrypt credentials internally
 * Threefish_512_OCB: used to encrypt and authenticate credential file

Suppoort
--------
 * Currently only *nix operating systems

Future Goals
------------
 * Add comprehensive unit test coverage
 * Develop a GUI
 * Get it to run on Android
 * Get it to run on Windows
 * Ensure it runs on Mac OS X
 * Get rid of /dev/urandom dependency
