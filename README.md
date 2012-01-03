# DES (Data Encryption Standard)

## What?
An implementation of an old encryption algorithm in Ruby. DES is an _outdated_ and __weak__ encryption algorithm that has been replaced by AES.
DES is a symetric key algorithm, so both the parties need to have the same key to share information.

## Why?
* To learn Ruby
* To learn about DES in depth

## How?
* Generate a key
    `./des.rb --keygen`
* Encrypt a file
    `./des.rb --encrypt <filename> -key <filename>`
* Decrypt a file
    `./des.rb --decrypt <filename> -key <filename>`

## Who?

Written by Andrew Deck. [@andrewdeck](http://twitter.com/andrewdeck)

## Resources
A link to the document that contains the specifications for DES. [fips46-3.pdf](http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf)
