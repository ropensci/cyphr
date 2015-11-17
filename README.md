# encryptr

> Enryption Wrappers

[![Linux Build Status](https://travis-ci.org/dide-tools/encryptr.svg?branch=master)](https://travis-ci.org/dide-tools/encryptr)

[![Windows Build status](https://ci.appveyor.com/api/projects/status/github/dide-tools/encryptr?svg=true)](https://ci.appveyor.com/project/dide-tools/encryptr)
[![](http://www.r-pkg.org/badges/version/encryptr)](http://www.r-pkg.org/pkg/encryptr)

Encryption wrappers, using low-level support from [`sodium`](https://github.com/jeroenooms/sodium).  This package is designed to be extremely easy to use, rather than the most secure thing (you're using R, remember).

The use case is a group of researchers who are collaborating on a dataset that cannot be made public, for example containing sensitive data.  However, they have decided or need to store it in a setting that they are not 100% confident about the security of the data.  So encrypt the data at each read/write.

There will need to be some support for key handling, to match a couple of common workflows.

## Encrypt / decrypt a file

```r
cfg <- config_symmetric("~/.encryptr/mykey")
encrypt_file("myfile", "myfile.encrypted")
decrypt_file("myfile.encrypted", "myfile.clear")
```

## Wrappers around R's file functions

Decide on a style of encryption and create a `encryptr_config` object (with `config_symmetric`, `config_public` and `config_authenticated`) and wrap the file-producing function with `encrypt`, and the file-consuming function with `decrypt`:

```r
cfg <- config_symmetric("~/.encryptr/mykey")
encrypt(saveRDS(iris, "myfile.rds"), cfg)
dat <- decrypt(readRDS("myfile.rds"), cfg)
identical(dat, iris) # yay
```

## Why not a connection object?

A proper connection could be nice but there are two issues stopping this:

1. `sodium` does not support streaming encryption/decrption.  It might be possible (bindings to node and swift have it).  In general this would be great and allow the sort of cool things you can do with streaming large data in curl.
2. R plays pretty loose and free with creating connections when given a filename; `readRDS`/`saveRDS` will open files with decompression on in binary mode, `read.csv`/`write.csv` don't.  `write.table` adds encoding information when openning the connection object.  The logic around what happens is entirely within the functions themselves so is hard to capture in a general way.
3. Connection objects look like a pain to write.

There are still problems with the approach I've taken:

* Appending does not work: we'd need to unencrypt the file first for that to be OK.  This is an issue for `write.table`, but not `writeLines`.
* Non-file arguments are going to suck (though it's possible that something could be done to detect connections)
