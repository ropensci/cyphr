## ---
## title: "Data Encryption"
## author: "Rich FitzJohn"
## date: "`r Sys.Date()`"
## output: rmarkdown::html_vignette
## vignette: >
##   %\VignetteIndexEntry{Data Encryption}
##   %\VignetteEngine{knitr::rmarkdown}
##   %\VignetteEncoding{UTF-8}
## ---

##+ echo=FALSE, results="hide"
options(encryptr.user.path=tempfile())
ssh_keygen(getOption("encryptr.user.path"), FALSE)
unlink("data", recursive=TRUE)

library(encryptr)

## The scenario:

## A group of people are working on a sensitive data set that for
## practical reasons needs to be stored in a place that we're not 100%
## happy with the securtity (e.g., dropbox).  If the data can be
## stored encrypted but everyone in the group can still read and write
## the data then we've improved the situation somewhat.

## The general proceedure is this:
##
## 1. A person will set up a set of personal keys and a key for the
## data.  The data key will be encrypted with their personal key so
## they have access to the data but nobody else does.  At this point
## the data can be encrypted.
##
## 2. Additional users set up personal keys and request access to the
## data.  Anyone with access to the data can grant access to anyone
## else.

## We'll store data in the directory `data`; at present there is
## nothing there.
data_dir <- "data"
dir.create(data_dir)
dir(data_dir)

## **First**, create a set of keys.  These will be shared across all
## projects and stored away from the data.  Ideally one would do this
## with `ssh-keygen` at the command line, following one of the many
## guides available.  A utility function (which simply calls
## `ssh-keygen` for you) is available. though.  You will need to
## generate a key on each computer you want access from.  Don't copy
## the key around.

## **Second**, create a key for the data and encrypt that key with
## your personal key.
data_admin_init(data_dir)

## This command can be run multiple times safely
data_admin_init(data_dir)

## **Third**, you can add encrypted data to the directory (or to
## anywhere really).  When run, `config_data` will verify that it can
## actually decryt things.
cfg <- config_data(data_dir)

## This object can be used with all the `encryptr` functions:
filename <- file.path(data_dir, "iris.rds")
encrypt(saveRDS(iris, filename), cfg)
dir(data_dir)

## The file is encrypted:
##+ error=TRUE
readRDS(filename)

## But we can decrypt it:
head(decrypt(readRDS(filename), cfg))

## **Fourth**, have someone else join in.  To simulate another person
## here, I'm going to pass an argument `user2` though.  If run on an
## actually different computer this would not be needed; this is just
## to simulate two users in a single session for this vignette (see
## minimal example below).
user2 <- tempfile()
ssh_keygen(user2, FALSE)

## We're going to assume that the user can read and write to the data.
## This is the case for my use case where the data are stored on
## dropbox and will be the case with github based distribution, though
## there would be a pull request step in here.

## This user cannot read the data:
##+ error=TRUE
cfg2 <- config_data(data_dir, user2)

## But `user2` is your collaborator and needs access.  What they need
## to do is run:
data_request_access(data_dir, user2)

## (ordinarily you would not need the `user2` bit here; that's just
## there because this is all done in one R session).

## The user should the send an email to someone with access and quote
## the hash in the message above.

## **Fifth**, back on the first computer we can authorise the second
## user.  First, see who has requested access:
req <- data_admin_list_requests(data_dir)
req

## We can see the same hash here as above (``r names(req)[[1]]``)

## ...and then grant access to them with the `data_admin_authorise` function.
data_admin_authorise(data_dir, yes=TRUE)

## which has cleared the request queue:
data_admin_list_requests(data_dir)

## and added it to our set of keys:
data_admin_list_keys(data_dir)

## **Finally**, as soon as the authorisation has happened, the user
## can encrypt and decrypt files:
cfg2 <- config_data(data_dir, user2)
head(decrypt(readRDS(filename), cfg2))

## ## Minimal example

## As above, but with less discussion:

##+ echo=FALSE, results="hide"
unlink(data_dir, recursive=TRUE)
unlink(user2, recursive=TRUE)
unlink(getOption("encryptr.user.path"), recursive=TRUE)
dir.create(data_dir)

## Setup, on computer 1:
data_user_init()
data_admin_init(data_dir)

## Encrypt a file:
encrypt(saveRDS(iris, filename), config_data(data_dir))

## Request access, on computer 2:
##+ echo=FALSE
oo <- options(encryptr.user.path=user2)
##+ echo=TRUE
data_user_init()
hash <- data_request_access(data_dir)
##+ echo=FALSE
options(oo)

## Authorise, on computer 1:
data_admin_authorise(data_dir, yes=TRUE)

## Read data, on computer 2:
##+ echo=FALSE
oo <- options(encryptr.user.path=user2)
##+ echo=TRUE
head(decrypt(readRDS(filename), config_data(data_dir)))
##+ echo=FALSE
options(oo)

## ## Details & disclosure

## Encryption does not work through security through obscurity; it
## works because we can rely on the underlying maths enough to be open
## about how things are stored and where.

## Most encryption libraries work require some degree of security in
## the underlying software.  Because of the way R works this is very
## difficult to guarantee; it is trivial to rewrite code in running
## packages to skip past verification checks.  So this package is
## _not_ designed to (or able to) avoid exploits in your running code;
## an attacker could intercept your private keys, the private key to
## the data, or skip the verification checks that are used to make
## sure that the keys you load are what they say they are.  However,
## the _data_ are safe; only people who have keys to the data will be
## able to read it.

## Encryptr uses two different encryption algorithms; it uses rsa
## encryption via the `openssl` package for user keys, because there
## is a common file format for these keys so it makes user
## configuration easier.  It uses the modern sodium package (and
## through that the libsodium library) for data encryption because it
## is very fast and simple to work with.  This does leave two possible
## points of weakness as a vulnerability in either of these libraries
## could lead to an exploit that could allow decryption of your data.

## Each user has a public/private key pair.  Typically this is in
## `~/.ssh/id_rsa.pub` and `~/.ssh/id_rsa`, and if found these will be
## used.  Alternatively the location of the keypair can be stored
## elsewhere and pointed at with the `USER_KEY` or `USER_PUBKEY`
## environment variables, or with the package option
## `encryptr.user.path`.  The key may be password protected (and this
## is recommended!) and the password will be requested without ever
## echoing it to the terminal.

## The data directory has a hidden directory `.encryptr` in it.  This
## does not actually need to be stored with the data but it makes
## sense to (there are workflows where data is stored remotely where
## storing this directory might make sense).  This directory contains
## a number of files; one for each person who has access to the data.
## Each file is stored in RDS format and is a list with elements:
##
## * user: the reported user name of the person who created request for data
## * host: the reported computer name
## * date: the time the request was generated
## * pub: the rsa public key of the user
## * signature: the signature of the contents of "user", "host",
##   "date", "pub".  This ensures that the data have not been changed
##   since they were created.
## * key: the data key, encrypted with the user key.  Without the
##   private key, this cannot be used.  With the user's private key
##   this can be used to generate the symmetric key to the data.
##
## (note that the verification relies on the package code not being
## attacked, and given R's highly dynamic nature an attacker could
## easily swap out the definition for the verification function with
## something that always returns `TRUE`.)

## This directory will contain a set of encrypted keys; these keys
## belong to different users and can be decrpted using their private
## keys.

## When an authorised user creates the `config_data` object, the package:
##
## * reads their private user key
## * reads the encrypted data key from the data directory
## * decrypts the data symmetric key, using the user's private key

## ## Limitations

## In the dropbox scenario, non-password protected keys will afford
## only limited protection.  This is because even though the keys and
## data are stored separately on dropbox, they will be in the same
## place on a local computer; if that computer is lost then the only
## thing preventing an attacker recovering the data is security
## through obscuritty (the data would appear to be random junk but
## they will be able to run your analysis scripts as easily as you
## can).  Password protected keys will improve this situation
## considerably as without a password the data cannot be recovered.

## The data and the key to encrypt it are not encrypted during a
## running R session.  R allows arbitrary modification of code at
## runtime so this package provides no security from the point where
## the data can be decrypted.  If your computer was compromised then
## stealing the data while you are running R should be assumed to be
## straightforward.

##+ echo=FALSE, results="hide"
unlink(data_dir, recursive=TRUE)
