## ---
## title: "Introduction"
## author: "Rich FitzJohn"
## date: "`r Sys.Date()`"
## output: rmarkdown::html_vignette
## vignette: >
##   %\VignetteIndexEntry{Introduction}
##   %\VignetteEngine{knitr::rmarkdown}
##   %\VignetteEncoding{UTF-8}
## ---

##+ echo=FALSE, results="hide"
local({
  path <- tempfile()
  encryptr::ssh_keygen(path, FALSE)
  Sys.setenv(USER_KEY=path)
})

## This package tries to smooth over some of the differences in
## encryption approaches (symmetric vs asymmetric, sodium vs openssl)
## to provide a simple interface for users who just want to encrypt or
## decrypt things.  My main motivation for writing this package is
## described in the [data workflow](data.html) vignette but
## implementing that requires a few features that might be generally
## useful.

## This vignette works through the basic functionality of the package.
## It does not offer much in the way of an introduction to encryption
## itself; for that see the excellent vignettes in the `openssl` and
## `sodium` packages.  This package is a thin wrapper for those
## packages.

## # Keys and the like

## To encrypt anything we need a key.  There are two sorts of key
## "types" we will concern ourselves with here "symmetric" and
## "asymmetric".
##
## * "symmetric" keys are used for storing secrets that multiple
##   people need to access.  Everyone has the same key (which is just
##   a bunch of bytes) and with that we can either encrypt data or
##   decrypt it.
##
## * a "key pair" is a public and a private key; this is used in
##   communication.  You hold a private key that nobody else ever sees
##   and a public key that you can copy around all over the show.
##   These can be used for a couple of different patterns of
##   communication (see below).

## We support key pairs from `openssl` and from `sodium` and symmetric
## keys from `sodium`.  In the rest of the package I use key pair from
## `openssl` to encrypt a `sodium` symmetric key.  The reason for this
## is that openssl keys have a common file format and many people have
## one already (whereas I do not see that `sodium` has anything like
## this).  On the other hand, `sodium` is really fast modern so it's
## nice to use that for dealing with potentially large amounts of
## data.

## ## Symmetric keys (`sodium`)

## A `sodium` key is literally just 32 bytes of random data.
key <- sodium::keygen()
key

## Because the key is not readily idenfiable as a key we wrap it up
## with \code{config_sodium_symmetric} (all of the approaches will
## work this way).
cfg <- encryptr::config_sodium_symmetric(key)

## With this we can use the encryption functions in the package (see below)

## ## Asymmetric keys (`openssl`)
pair <- encryptr::config_openssl()

## These will look, in turn, at:
##
## * the argument `path` (`NULL` by default) to `config_openssl`
## * the environment variable (`USER_KEY` or `USER_PUBKEY`)
## * the path `~/.ssh/id_rsa.pub`
##
## The path provided can be the directory containing `id_rsa.pub` and
## `id_rsa` or a path to either and hopefully the right thing will
## happen.  If your private key is password-protected (a *very* good
## idea) you will be prompted for your password.

## ## Asymmetric keys (`sodium`)

## This is currently less useful practically because there is no
## standard format for storing keys (TODO: complete)

## # Encrypting things

## ## Files, via the high level interface

## This is the most user-friendly way of using the package.  The
## package provides a pair of functions `encrypt` and `decrypt` that
## wrap file writing and file reading functions.  In general you would
## use `encrypt` when writing a file and `decrypt` when reading one.
## They're designed to be used like so:

## Suppose you have a super-secret object that you want to share privately
cfg <- encryptr::config_sodium_symmetric(sodium::keygen())
x <- list(a = 1:10, b = "don't tell anyone else")

## If you save this to disk with `saveRDS` it will be readable by
## everyone.  But if you encrypted the file that `saveRDS` produced it
## would be protected:
encryptr::encrypt(saveRDS(x, "secret.rds"), cfg)

## (see below for some more details on how this works).

## This file cannot be read with `readRDS`:

##+ error=TRUE
readRDS("secret.rds")

## but if we wrap the call with `decrypt` and pass in the config
## object it can be decrypted and read:
encryptr::decrypt(readRDS("secret.rds"), cfg)

## What happens in the call above is some moderately nasty call
## rewriting.  If this bothers you, you should just use `encrypt_file`
## / `decrypt_file` and make sure to clean up after yourself.

## The `encrypt` function inspects the call in the first argument
## passed to it and works out for the function provided (`saveRDS`)
## which argument corresponds to the filename (here `"secret.rds"`).
## It then rewrites the call to write out to a temporary file (using
## `tempfile()`).  Then it calls `encrypt_file` (see below) on this
## temporary file to create the file asked for (`"secret.rds"`).  Then
## it deletes the temporary file, though this will also happen in case
## of an error in any of the above.

## The `decrypt` function works similarly.  It insepects the call and
## detects that the first argument represents the filename.  It
## decrypts that file to create a temporary file, and then runs
## `readRDS` on that file.  Again it will delete the temporary file on
## exit.

## The functions supported via this interface are:

## * `readLines` / `writeLines`
## * `readRDS` / `writeRDS`
## * `read` / `save`
## * `read.table` / `write.table`
## * `read.csv` / `read.csv2` / `write.csv`
## * `read.delim` / `read.delim2`

## But new functions can be added with the `rewrite_register`
## function.  For example, to support the excellent
## [rio](https://cran.r-project.org/web/packages/rio) package, whose
## `import` and `export` functions take the filename `file` you could
## use:
##
## ```r
## encryptr::rewrite_register("rio", "import", "file")
## encryptr::rewrite_register("rio", "export", "file")
## ```
##
## now you can read and write tabular data into and out of a great
## many different file formats with encryption with calls like
##
## ```r
## encryptr::encrypt(rio::export(mtcars, "file.json"), cfg)
## encryptr::decrypt(rio::import("file.json"), cfg)
## ```

## The functions above use [non standard evaluation](http://adv-r...)
## and so may not be suitable for programming or use in packages.  An
## "escape hatch" is provided via `encrypt_` and `decrypt_` where the
## first argument is a quoted expression.
encryptr::encrypt_(quote(saveRDS(x, "secret.rds")), cfg)
encryptr::decrypt_(quote(readRDS("secret.rds")), cfg)

## ## Objects
cfg <- encryptr::config_sodium_symmetric(sodium::keygen())

## Here's an object to encrypt:
obj <- list(x=1:10, y="secret")

## This creates a bunch of raw bytes corresponding to the data (it's
## not really possible to print this as anything nicer than bytes).
secret <- encryptr::encrypt_object(obj, NULL, cfg)
secret

## (the `NULL` second argument to the `encrypt_object` call indicates
## we don't want to write to file but instead want to return the data
## itself, like R's `serialize` function).

## The data can be decrypted with the `decrypt_object` function:
encryptr::decrypt_object(secret, cfg)

## ## Strings

## For the case of strings we can do this in a slightly more
## lightweight way (the above function routes through `serialize` /
## `deserialize` which can be slow and will create larger objects than
## using `charToRaw` / `rawToChar`)
secret <- encryptr::encrypt_string("secret", NULL, cfg)
secret

## and decrypt:
encryptr::decrypt_string(secret, cfg)

## ## Plain raw data

## If these are not enough for you, you can work directly with raw
## objects (bunches of bytes) by using `encrypt_data`:
dat <- sodium::random(100)
dat # some random bytes

secret <- encryptr::encrypt_data(dat, NULL, cfg)
secret

## Decrypted data is the same as a the original data
identical(encryptr::decrypt_data(secret, NULL, cfg), dat)

## ## Files

## ## Send a secret message to someone

## Because it's not totally obvious, here is how two users can use
## openssl rsa keypairs to share a secret key.  This is the idea
## underlying the [workflow discussed elsewhere](data.html).

## First, generate a keypair.
path_pair <- encryptr::ssh_keygen(tempfile(), FALSE)
pair <- encryptr::config_openssl(path_pair)

## Next we can load the *public key* from the pair above.  Assume that
## the public key has been swapped around by the users by this point,
## and that the code here is being run on a different users's machine.
pub <- encryptr::config_openssl(path_pair, private=FALSE)

## Then we'll generate a sodium symmetric key to share.
## Alternatively, this could be any data.
data <- sodium::keygen()

## Then we can use the public key of user2 to encrypt a message that
## only they can read:
secret <- encryptr::encrypt_data(data, NULL, pub)

## The user can then decrypt the data this way:
encryptr::decrypt_data(secret, NULL, pair)

## Nobody else but that user can decrypt the data.

## ## Secure message exchange

## If two users both know each others public keys (and their own
## private keys) they can securely message each other.  This means
## that the first user will encrypt a message with their private key
## and the other users' public key and only the other user can decrypt
## the message _and_ they know it has come from the first user.  This
## is not currently supported but will be available by passing the
## public and private keys explicitly to `config_openssl` in a future
## version.

## (TODO: complete)

##+ echo=FALSE, results="hide"
Sys.unsetenv("USER_KEY")
file.remove("secret.rds")
