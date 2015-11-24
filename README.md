# encryptr

> Enryption Wrappers

[![Linux Build Status](https://travis-ci.org/dide-tools/encryptr.svg?branch=master)](https://travis-ci.org/dide-tools/encryptr)

[![Windows Build status](https://ci.appveyor.com/api/projects/status/github/dide-tools/encryptr?svg=true)](https://ci.appveyor.com/project/dide-tools/encryptr)

Encryption wrappers, using low-level support from [`sodium`](https://github.com/jeroenooms/sodium).  This package is designed to be extremely easy to use, rather than the most secure thing (you're using R, remember).

The use case is a group of researchers who are collaborating on a dataset that cannot be made public, for example containing sensitive data.  However, they have decided or need to store it in a setting that they are not 100% confident about the security of the data.  So encrypt the data at each read/write.

There will need to be some support for key handling, to match a couple of common workflows.

## Objects to handle keys:

Decide on a style of encryption and create a `encryptr_config` object (with `config_symmetric`, `config_public` and `config_authenticated`):

```r
cfg <- config_symmetric("~/.encryptr/mykey")
```

## Encrypt / decrypt a file

```r
encrypt_file("myfile", "myfile.encrypted")
decrypt_file("myfile.encrypted", "myfile.clear")
```

## Wrappers around R's file functions

To encrypt the output of a file producing command, wrap it in `encrypt`

```r
encrypt(saveRDS(iris, "myfile.rds"), cfg)
```

To decrypt the a file to feed into a file consuming command, wrap it in `decrypt`:

```r
dat <- decrypt(readRDS("myfile.rds"), cfg)
```

The roundtrip preserves the data:

```r
identical(dat, iris) # yay
```

But without the key, it cannot be read:

```r
readRDS("myfile.rds") # unknown format
```

The above commands work through computing on the language, rewriting the `readRDS` and `saveRDS` commands.  Commands for reading and writing tabular and plain text files (`read.csv`, `readLines`, etc) are also supported, and the way the rewriting is done is designed to be extensible.

With (probably) some limitations, the argument to the wrapped functions can be connection objects.  In this case the *actual* command is written to a file and the contents of that file are encrypted and written to the connection.  When reading/writing multiple objects from/to a single connection though, this is likely to go very badly.

## Workflow support

It's possible that this means there are two packages here, but I have a single use case so they're together for now at least.  The package contains support for a group of people are working on a sensitive data set.  The data will be stored with a symmetric key.  However, we never actually store the key directly, instead we'll store a copy that is encrypted with the user key.  Any user with access to the data can authorise another user to access the data.  This is described in more detail in the [vignette](http://dide-tools.github.io/encryptr/vignettes/data.html) (in R: `vignette("data", package="encryptr")`).

## Why not a connection object?

A proper connection could be nice but there are two issues stopping this:

1. `sodium` does not support streaming encryption/decrption.  It might be possible (bindings to node and swift have it).  In general this would be great and allow the sort of cool things you can do with streaming large data in curl.
2. R plays pretty loose and free with creating connections when given a filename; `readRDS`/`saveRDS` will open files with decompression on in binary mode, `read.csv`/`write.csv` don't.  `write.table` adds encoding information when openning the connection object.  The logic around what happens is entirely within the functions themselves so is hard to capture in a general way.
3. Connection objects look like a pain to write.

There are still problems with the approach I've taken:

* Appending does not work: we'd need to unencrypt the file first for that to be OK.  This is an issue for `write.table`, but not `writeLines`.
* Non-file arguments are going to suck (though it's possible that something could be done to detect connections)
