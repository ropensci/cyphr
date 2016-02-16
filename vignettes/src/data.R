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
encryptr::ssh_keygen(getOption("encryptr.user.path"), FALSE)
unlink("data", recursive=TRUE)

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
## the key around.  If you lose your user key you will lose access to
## the data!

## **Second**, create a key for the data and encrypt that key with
## your personal key.  Note that the data key is never stored directly
## - it is always stored encrypted by a personal key.
encryptr::data_admin_init(data_dir)

## The data key is very important.  If it is deleted, then the data
## cannot be decrypted.  So keep the directory `data_dir/.encryptr`
## safe!  Ideally add it to your version control system so that it
## cannot be lost.

## This command can be run multiple times safely; if it detects it has
## been rerun and the data key will not be regenerated.
encryptr::data_admin_init(data_dir)

## **Third**, you can add encrypted data to the directory (or to
## anywhere really).  When run, `encryptr::config_data` will verify that it can
## actually decrypt things.
cfg <- encryptr::config_data(data_dir)

## This object can be used with all the `encryptr` functions:
filename <- file.path(data_dir, "iris.rds")
encryptr::encrypt(saveRDS(iris, filename), cfg)
dir(data_dir)

## The file is encrypted:
##+ error=TRUE
readRDS(filename)

## But we can decrypt it:
head(encryptr::decrypt(readRDS(filename), cfg))

## **Fourth**, have someone else join in.  To simulate another person
## here, I'm going to pass an argument `user2` though to the
## functions.  If run on an actually different computer this would not
## be needed; this is just to simulate two users in a single session
## for this vignette (see minimal example below).  Typically this user
## would also not use the `encryptr::ssh_keygen` function but use the
## `ssh-keygen` command from their shell (not from R).
user2 <- tempfile()
encryptr::ssh_keygen(user2, FALSE)

## We're going to assume that the user can read and write to the data.
## This is the case for my use case where the data are stored on
## dropbox and will be the case with github based distribution, though
## there would be a pull request step in here.

## This user cannot read the data, though trying to will print a
## message explinaing how you might request access:
##+ error=TRUE
cfg2 <- encryptr::config_data(data_dir, user2)

## But `user2` is your collaborator and needs access.  What they need
## to do is run:
encryptr::data_request_access(data_dir, user2)

## (again, ordinarily you would not need the `user2` bit here)

## The user should the send an email to someone with access and quote
## the hash in the message above.

## **Fifth**, back on the first computer we can authorise the second
## user.  First, see who has requested access:
req <- encryptr::data_admin_list_requests(data_dir)
req

## We can see the same hash here as above (``r names(req)[[1]]``)

## ...and then grant access to them with the
## `encryptr::data_admin_authorise` function.
encryptr::data_admin_authorise(data_dir, yes=TRUE)

## If you do not specify `yes=TRUE` will prompt for confirmation at
## each key added.

## This has cleared the request queue:
encryptr::data_admin_list_requests(data_dir)

## and added it to our set of keys:
encryptr::data_admin_list_keys(data_dir)

## **Finally**, as soon as the authorisation has happened, the user
## can encrypt and decrypt files:
cfg2 <- encryptr::config_data(data_dir, user2)
head(encryptr::decrypt(readRDS(filename), cfg2))

## ## Minimal example

## As above, but with less discussion:

##+ echo=FALSE, results="hide"
unlink(data_dir, recursive=TRUE)
dir.create(data_dir)

## Setup, on computer 1:
encryptr::data_admin_init(data_dir)

## Encrypt a file:
encryptr::encrypt(saveRDS(iris, filename), encryptr::config_data(data_dir))

## Request access, on computer 2:
##+ echo=FALSE
oo <- options(encryptr.user.path=user2)
##+ echo=TRUE
hash <- encryptr::data_request_access(data_dir)
##+ echo=FALSE
options(oo)

## Authorise, on computer 1:
encryptr::data_admin_authorise(data_dir, yes=TRUE)

## Read data, on computer 2:
##+ echo=FALSE
oo <- options(encryptr.user.path=user2)
##+ echo=TRUE
head(encryptr::decrypt(readRDS(filename), encryptr::config_data(data_dir)))
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

## The data directory has a hidden directory `.encryptr` in it.
dir("data", all.files=TRUE, no..=TRUE)

## This does not actually need to be stored with the data but it
## makes sense to (there are workflows where data is stored remotely
## where storing this directory might make sense).  This directory
## contains a number of files; one for each person who has access to
## the data.
dir(file.path("data/.encryptr"))
names(encryptr::data_admin_list_keys("data"))

## (the file `test` is a small file encrypted with the data key used
## to verify everything is working OK).

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

h <- names(encryptr::data_admin_list_keys("data"))[[1]]
readRDS(file.path("data/.encryptr", h))

## (In the `key` element, the elements `iv`, `session` are created by
## `openssl` as one-time data, and `data` is the encrypted data
## itself; see the `openssl` package for more details.)

## You can see that the hash of the public key is the same as name of
## the stored file here (which is used to prevent collisions when
## multiple people request access at the same time).
h

## When a request is posted it is an RDS file with all of the above
## except for the `key` element, which is added during authorisation.
##
## (Note that the verification relies on the package code not being
## attacked, and given R's highly dynamic nature an attacker could
## easily swap out the definition for the verification function with
## something that always returns `TRUE`.)
##
## When an authorised user creates the `config_data` object (which
## allows decryption of the data) `secret` will:
##
## * read their private user key (probably from `~/.ssh/id_rsa`)
## * read the encrypted data key from the data directory (the `$key`
##   element from the list above).
## * decrypt this data key using their user key to yield the the data
##   symmetric key.

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
