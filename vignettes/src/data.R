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

## ## Details

## Each user has a directory with a public and private key in it.  The
## private key is just 32 bytes of binary data, and the public key is
## a human-readable file with a little additional metadata to make it
## easier for people to associate keys with people.

## The data directory will have a hidden directory `.encryptr` in
## it. This does not actually have to be stored with the data but it
## makes sense to.  This directory will contain a set of encrypted
## keys; these keys belong to different users and can be decrpted
## using their private keys.

## When an authorised user creates the `config_data` object, the package:
##
## * reads their encrypted key from the data directory
## * reads their private key from their user directory
## * decrypts the data key to give a "symmetric" key which will be the
##   same for all users (but is never directly stored anywhere).

## Public keys are stored in the requests directory and the data
## directory by their hash; a digest of all the data in the key.  This
## should mean that verifying the key "out of band" (e.g., over email)
## is easy.  But practically it should not matter much.  Signing the
## keys would probably be a better idea.  In any case, this hash is
## checked when the key is opened by the authorise or list commands.

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
