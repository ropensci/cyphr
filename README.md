

# cyphr

[![Project Status: WIP - Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](http://www.repostatus.org/badges/latest/wip.svg)](http://www.repostatus.org/#wip)
[![Linux Build Status](https://travis-ci.org/richfitz/cyphr.svg?branch=master)](https://travis-ci.org/richfitz/cyphr)
 [![Windows Build status](https://ci.appveyor.com/api/projects/status/github/richfitz/cyphr?svg=true)](https://ci.appveyor.com/project/richfitz/cyphr)
[![codecov.io](https://codecov.io/github/richfitz/cyphr/coverage.svg?branch=master)](https://codecov.io/github/richfitz/cyphr?branch=master)

Encryption wrappers, using low-level support from [`sodium`](https://github.com/jeroenooms/sodium) and [`openssl`](https://github.com/jeroenooms/openssl).  This package is designed to be easy to use, rather than the most secure thing (you're using R, remember).

It provides high level functions to:

* Encrypt and decrypt
  * **strings**: `encrypt_string` / `decrypt_string`
  * **objects**: `encrypt_object` / `decrypt_object`
  * **raw data**: `encrypt_data` / `decrypt_data`
  * **files**: `encrypt_file` / `decrypt_file`
* User-friendly wrappers (`encrypt` and `decrypt`) around R's file reading and writing functions that enable transparent encryption (support included for `readRDS`/`writeRDS`, `read.csv`/`write.csv`, etc).

The package aims to make encrypting and decrypting as easy as


```r
cyphr::encrypt(save.csv(dat, "file.csv"), key)
```

and


```r
dat <- cyphr::decrypt(read.csv("file.csv", stringsAsFactors = FALSE), key)
```

In addition, the package implements a workflow that allows a group to securely share data by encrypting it with a shared ("symmetric") key that is in turn encrypted with each users ssh keys.  The use case is a group of researchers who are collaborating on a dataset that cannot be made public, for example containing sensitive data.  However, they have decided or need to store it in a setting that they are not 100% confident about the security of the data.  So encrypt the data at each read/write.

## Objects to handle keys:

Decide on a style of encryption and create a key object

* `key_sodium`: [Symmetric encryption, using sodium](http://127.0.0.1:19184/library/sodium/doc/intro.html#secret-key-encryption) -- everyone shares the same key (which must be kept secret!) and can encrypt and decrpt data with it.  This is used as a building block but is inflexible because of the need to keep the key secret.
* `keypair_sodium`: [Public key encryption](http://127.0.0.1:19184/library/sodium/doc/intro.html#public-key-encryption) -- this lets people encrypt messages using your public key that only you can read using your private key.
* `key_openssl`: [Symmetric encryption using openssl]
* `keypair_openssl`: Public key encryption, using [openssl](https://cran.r-project.org/web/packages/openssl) (see `?encrypt_envelope` in the the `openssl` package.

To generate keys, you really should read the underling documentation in the `sodium` or `openssl` packages!  The `sodium` keys do not have a file format: they are simply random data.  So a secret symmetric key in `sodium` might be:


```r
k <- sodium::keygen()
k
```

```
##  [1] 9f a1 af 9c 70 a7 c2 6e 35 aa 03 a3 2d c5 18 13 da eb a4 ce 37 9b bc
## [24] cf 8e c1 3c 3a 40 5e 73 0e
```

With this key we can create the `key_sodium` object:


```r
key <- cyphr::key_sodium(k)
key
```

```
## <cyphr_key: sodium>
```

If the key was saved to file that would work too:

If you load a password protected ssh key you will be prompted for your passphrase.  `cyphr` will ensure that this is not echoed onto the console.


```r
key <- cyphr::key_openssl()
key
## Please enter private key passphrase:
```

## Encrypt / decrypt a file

If you have files that already exist and you want to encrypt or decrypt, the functions `cyphr::encrypt_file` and `cyphr::decrypt_file` will do that (these are workhorse functions that are used internally throughout the package)


```r
saveRDS(iris, "myfile")
cyphr::encrypt_file("myfile", key, "myfile.encrypted")
```

The file is encrypted now:


```r
readRDS("myfile.encrypted")
```

```
## Error in readRDS("myfile.encrypted"): unknown input format
```

Decrypt the file and read it:


```r
cyphr::decrypt_file("myfile.encrypted", key, "myfile.clear")
identical(readRDS("myfile.clear"), iris)
```

```
## [1] TRUE
```



## Wrappers around R's file functions

While encrypting files is nice, the aim of the package is

To encrypt the output of a file producing command, wrap it in `cyphr::encrypt`


```r
cyphr::encrypt(saveRDS(iris, "myfile.rds"), key)
```

To decrypt the a file to feed into a file consuming command, wrap it in `cyphr::decrypt`:


```r
dat <- cyphr::decrypt(readRDS("myfile.rds"), key)
```

The roundtrip preserves the data:

```r
identical(dat, iris) # yay
```

```
## [1] TRUE
```

But without the key, it cannot be read:

```r
readRDS("myfile.rds") # unknown input format
```

```
## Error in readRDS("myfile.rds"): unknown input format
```



The above commands work through computing on the language, rewriting the `readRDS` and `saveRDS` commands.  Commands for reading and writing tabular and plain text files (`read.csv`, `readLines`, etc) are also supported, and the way the rewriting is done is designed to be extensible.

With (probably) some limitations, the argument to the wrapped functions can be connection objects.  In this case the *actual* command is written to a file and the contents of that file are encrypted and written to the connection.  When reading/writing multiple objects from/to a single connection though, this is likely to go very badly.

Because `cyphr::encrypt` and `cyphr::decrypt` compute on the language, standard evaluation forms `cyphr::encrypt_` and `cyphr::decrypt_` are provided that take a quoted expression as their first argument.

### Supporting additional functions

The functions supported so far are:

* `readLines` / `writeLines`
* `readRDS` / `writeRDS`
* `read` / `save`
* `read.table` / `write.table`
* `read.csv` / `read.csv2` / `write.csv`
* `read.delim` / `read.delim2`

However, there are bound to be more functions that could be useful to add here (e.g., `readxl::read_excel`).  Either pass the name of the file argument to `cyphr::encrypt` / `cyphr::decrypt` as

```r
cyphr::decrypt(readxl::read_excel("myfile.xlsx"), key, file_arg = "path")
```

or *register* the function with the package using `rewrite_register`:

```r
cyphr::rewrite_register("readxl", "read_excel", "path")
```

Then you can use

```r
cyphr::decrypt(readxl::read_excel("myfile.xlsx"), key)
```

to decrypt the file.

## Workflow support

It's possible that this means there are two packages here, but I have a single use case so they're together for now at least.  The package contains support for a group of people are working on a sensitive data set.  The data will be stored with a symmetric key.  However, we never actually store the key directly, instead we'll store a copy that is encrypted with the user key.  Any user with access to the data can authorise another user to access the data.  This is described in more detail in the [vignette](http://richfitz.github.io/cyphr/vignettes/data.html) (in R: `vignette("data", package = "cyphr")`).

## Why not a connection object?

A proper connection could be nice but there are two issues stopping this:

1. `sodium` does not support streaming encryption/decrption.  It might be possible (bindings to node and swift have it).  In general this would be great and allow the sort of cool things you can do with streaming large data in curl.
2. R plays pretty loose and free with creating connections when given a filename; `readRDS`/`saveRDS` will open files with decompression on in binary mode, `read.csv`/`write.csv` don't.  `write.table` adds encoding information when openning the connection object.  The logic around what happens is entirely within the functions themselves so is hard to capture in a general way.
3. Connection objects look like a pain to write.

There are still problems with the approach I've taken:

* Appending does not work: we'd need to unencrypt the file first for that to be OK.  This is an issue for `write.table`, but not `writeLines`.
* Non-file arguments are going to suck (though it's possible that something could be done to detect connections)

In the end, you can always write things out however you like and use `encrypt_file` to encrypt the file afterwards.

## Why are wrappers needed?

The low level functions in `sodium` and `openssl` work with raw data, for generality.  Few users encounter raw vectors in their typical use of R, so these require serialisation.  Most of the encryption involves a little extra random data (the "nonce" in `sodium` and similar additional pieces with `openssl`).  These need storing with the data, and then separating from the dadta when decryption happens.

## Installation

To install `cyphr` from github:

```r
remotes::install_github("richfitz/cyphr", upgrade = FALSE)
```

Note that [`libsodium`](https://download.libsodium.org/doc/) will be needed to compile the package. See [installation instructions](https://download.libsodium.org/doc/installation/index.html).
