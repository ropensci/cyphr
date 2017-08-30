

# cyphr

[![Project Status: WIP - Initial development is in progress, but there has not yet been a stable, usable release suitable for the public.](http://www.repostatus.org/badges/latest/wip.svg)](http://www.repostatus.org/#wip)
[![Linux Build Status](https://travis-ci.org/richfitz/cyphr.svg?branch=master)](https://travis-ci.org/richfitz/cyphr)
 [![Windows Build status](https://ci.appveyor.com/api/projects/status/github/richfitz/cyphr?svg=true)](https://ci.appveyor.com/project/richfitz/cyphr)
[![codecov.io](https://codecov.io/github/richfitz/cyphr/coverage.svg?branch=master)](https://codecov.io/github/richfitz/cyphr?branch=master)
[![](http://badges.ropensci.org/114_status.svg)](https://github.com/ropensci/onboarding/issues/114)

**WARNING: until this package reaches version 1, the format used internally to move data around may change without warning or regard for backward compatibility - this will make it very difficult to recover your data!  Once we reach version 1.0.0, we will be careful to support backward compatiblity**

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

## Installation

To install `cyphr` from github:

```r
remotes::install_github("richfitz/cyphr", upgrade = FALSE)
```

## Scope

The scope of the package is to protect data that has been saved to disk.  It is not designed to stop an attacker targeting the R process itself to determine the contents of sensitive data.  The package does try to prevent you accidently saving to disk the contents of sensitive information, including the keys that could decrypt such information.

## Objects to handle keys:

Decide on a style of encryption and create a key object

* `key_sodium`: Symmetric encryption, using [sodium](https://cran.r-project.org/web/packages/sodium) -- everyone shares the same key (which must be kept secret!) and can encrypt and decrypt data with it.  This is used as a building block but is inflexible because of the need to keep the key secret.
* `keypair_sodium`: Public key encryption with [sodium](https://cran.r-project.org/web/packages/sodium) -- this lets people encrypt messages using your public key that only you can read using your private key.
* `key_openssl`: Symmetric encryption using [openssl](https://cran.r-project.org/web/packages/openssl)
* `keypair_openssl`: Public key encryption, using [openssl](https://cran.r-project.org/web/packages/openssl), which has the big advantage that many people already have compatible (ssh) keys in standard places with standard file formats (see `?encrypt_envelope` in the the `openssl` package).

To generate keys, you really should read the underlying documentation in the `sodium` or `openssl` packages!  The `sodium` keys do not have a file format: they are simply random data.  So a secret symmetric key in `sodium` might be:


```r
k <- sodium::keygen()
k
```

```
##  [1] 28 c8 c3 d7 ca 08 5a 6c 83 9b a5 23 ab fe 28 ed 24 ca 40 84 5a f3 e2
## [24] 8f b2 de 8f 4d 0e 28 c0 de
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
## Please enter private key passphrase:
key
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

Encrypting files like the above risks leaving a cleartext version around.  If you want to wrap the output of something like `write.csv` or `saveRDS` you really have no choice but to write out the file first, encrypt it, and delete the clear version.  Making sure that this happens even if a step fails is error prone and takes a surprising number of repetitive lines of code.

Alternatively, to encrypt the output of a file producing command, just wrap it in `cyphr::encrypt`


```r
cyphr::encrypt(saveRDS(iris, "myfile.rds"), key)
```

Then to decrypt the a file to feed into a file consuming command, wrap it in `cyphr::decrypt`


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
readRDS("myfile.rds")
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

## Collaborating with encrypted data

Even with high-level functions to ease encrypting and decrypting things given a key, there is some work to be done to distribute a set of keys across a group of people who are working together so that everyone can encrypt and decrypt the data but so that the keys themselves are not compromised.

The package contains support for a group of people are working on a sensitive data set.  The data will be stored with a symmetric key.  However, we never actually store the key directly, instead we'll store a copy for each user that is encrypted with the user's key.  Any user with access to the data can authorise another user to access the data.  This is described in more detail in the [vignette](http://richfitz.github.io/cyphr/vignettes/data.html) (in R: `vignette("data", package = "cyphr")`).

## Why not a connection object?

A proper connection could be nice but there are at least three issues stopping this:

1. `sodium` does not support streaming encryption/decrption.  It might be possible (bindings to node and swift have it).  In general this would be great and allow the sort of cool things you can do with streaming large data in curl.
2. R plays pretty loose and free with creating connections when given a filename; `readRDS`/`saveRDS` will open files with decompression on in binary mode, `read.csv`/`write.csv` don't.  `write.table` adds encoding information when openning the connection object.  The logic around what happens is entirely within the functions themselves so is hard to capture in a general way.
3. Connection objects look like a pain to write.

There are still problems with the approach I've taken:

* Appending does not work: we'd need to unencrypt the file first for that to be OK
* Non-file arguments are going to suck (though it's possible that something could be done to detect connections)

In the end, you can always write things out however you like and use `encrypt_file` to encrypt the file afterwards.

## Why are wrappers needed?

The low level functions in `sodium` and `openssl` work with raw data, for generality.  Few users encounter raw vectors in their typical use of R, so these require serialisation.  Most of the encryption involves a little extra random data (the "nonce" in `sodium` and similar additional pieces with `openssl`).  These need storing with the data, and then separating from the data when decryption happens.

## Licence

MIT © [Rich FitzJohn](https://github.com/richfitz).

Please note that this project is released with a [Contributor Code of Conduct](CONDUCT.md). By participating in this project you agree to abide by its terms.
