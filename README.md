# DES (Data Encryption Standard)

## What?
An implementation of an old encryption algorithm in Ruby. DES is an _outdated_ and __weak__ encryption algorithm that has been replaced by AES.
DES is a symetric key algorithm, so both the parties need to have the same key to share information.

## Why?
* To learn Ruby
* To learn about DES in depth

## How?
* Generate a key
    `./des --keygen`
* Encrypt a file
    `./des --encrypt <filename> -key <filename>`
* Decrypt a file
    `./des --decrypt <filename> -key <filename>`

## Resources
[fips46-3.pdf](http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf)
