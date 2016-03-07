## NOTE: All functions here are arbitrarily prefixed with 'data'
## because they're the 'data workflow' part of the package.  I may
## move them elsewhere.
##
## It does make me wish there was some easy way (i.e., not local) of
## having namespaces that are file specific...
##
## The API functions are:
##
##   data_admin_init
##   data_admin_authorise (I don't think this is tested with hash)
##   data_admin_list_requests
##   data_admin_list_keys
##   data_request_access
##   config_data
##
## with most of these being admin functions that will be used fairly
## little; the config_data one is the only one people will need to use
## very often.

##' Encrypted data administration; functions for setting up, adding
##' users, etc.
##'
##' \code{data_admin_init} initialises the system; it will create a
##' data key if it does not exist and authorise you.  If it already
##' exists and you do not have access it will throw an error.
##'
##' \code{data_admin_authorise} authorises a key by creating a key to
##' the data that the user can use in conjunction with their personal
##' key.
##'
##' \code{data_admin_list_requests} lists current requests.
##'
##' \code{data_admin_list_keys} lists known keys that can access the
##' data.  Note that this is \emph{not secure}; keys not listed here
##' may still be able to access the data (if a key was authorised and
##' moved elsewhere for example).  Conversely, if the user has deleted
##' or changed their key they will not be able to access the data
##' despite the key being listed here.
##'
##' @title Encrypted data administration
##'
##' @param path_data Path to the data set.  We will store a bunch of
##'   things in a hidden directory within this path.  The default is
##'   to use the working directory of R, which should work well for
##'   things like RStudio projects.
##'
##' @param path_user Path to the directory with your user key.
##'   Usually this can be ommited.
##'
##' @param quiet Suppress printing of informative messages.
##' @export
##' @rdname data_admin
data_admin_init <- function(path_data=".", path_user=NULL, quiet=FALSE) {
  key <- data_check_path_user(path_user, quiet)

  if (!is_directory(path_data)) {
    stop("path_data must exist and be a directory")
  }
  path_enc <- data_path_encryptr(path_data)
  if (!data_check_path_data(path_data, fail=FALSE)) {
    workflow_log(quiet, "Generating data key")
    dir.create(path_enc, FALSE, TRUE)

    ## Now, the idea is to create a key for the data set:
    sym <- load_key_sodium_symmetric(sodium::keygen())

    ## NOTE: If anything below fails, this file needs deleting, as
    ## this is the file that we check to see if things are set up
    ## correctly (data_check_path_data()).
    path_test <- data_filename_test(path_data)
    encrypt(writeLines("encryptr", path_test), sym)
    on.exit(file.remove(path_test))
    decrypt(readLines(path_test), sym)

    workflow_log(quiet, "Authorising ourselves")

    ## Now, make a copy of the public key; probably what needs to
    ## happen here is that we authorise ourselves but this case is a
    ## little different because we already have the symmetric key.
    ## But this bit is shared; we need to copy the files around a
    ## bunch.
    ##
    tmp <- data_request_access(path_data, key, quiet=TRUE)
    on.exit(file.remove(data_path_request(path_data)))
    ## NOTE: here we can't use data_admin_authorise because we can't
    ## load the symmetric key from the files we're trying to write!
    dat <- data_pub_load(tmp, data_path_request(path_data))
    data_authorise_write(path_data, sym, dat, TRUE, quiet)
  } else {
    workflow_log(quiet, "Already set up")
  }

  workflow_log(quiet, "Verifying")
  x <- config_data(path_data, key, TRUE)
  on.exit() # disable possible file removals.
  invisible(TRUE)
}

##' @export
##' @rdname data_admin
##'
##' @param hash A vector of hashes to add.  If provided, each hash can
##'   be the binary or string representation of the hash to add.  Or
##'   omit to add each request.
##'
##' @param yes Skip the confirmation prompt?  If any request is
##'   declined then the function will throw an error on exit.
data_admin_authorise <- function(path_data=".", hash=NULL, path_user=NULL,
                                 yes=FALSE, quiet=FALSE) {
  data_check_path_data(path_data)

  path_req <- data_path_request(path_data)

  if (is.null(hash)) {
    keys <- data_admin_list_requests(path_data)
    workflow_log(
      quiet,
      ngettext(length(keys), "There is 1 request for access",
               sprintf("There are %d requests for access", length(keys))))
  } else if (is.character(hash)) {
    keys <- lapply(hash, data_pub_load, path_req)
  } else if (is.raw(hash)) {
    keys <- list(data_pub_load(hash, path_req))
  } else {
    stop("Invalid type for 'hash'")
  }

  if (length(keys) == 0L) {
    workflow_log(quiet, "No keys to add")
    return()
  }

  sym <- data_load_sym(path_data, path_user, quiet)

  nerr <- 0L
  handle_cancel <- function(e) {
    nerr <<- nerr + 1L
    message(e$message)
  }
  for (k in keys) {
    tryCatch(data_authorise_write(path_data, sym, k, yes, quiet),
             cancel_addition=handle_cancel)
  }
  nok <- length(keys) - nerr
  if (nok > 0) {
    workflow_log(quiet, "Added %d key%s", nok, ngettext(nok, "", "s"))
    if (using_git(path_data)) {
      users <- paste(vapply(keys, function(x) x$user, character(1)),
                     collapse=", ")
      path_enc <- sub("./", "", data_path_encryptr("."), fixed=TRUE)
      msg <- c("If you are using git, you will need to commit and push:",
               paste("    git add", path_enc),
               sprintf('    git commit -m "Authorised %s"', users),
               '    git push')
      workflow_log(quiet, paste(msg, collapse="\n"))
    }
  }
  if (nerr > 0L) {
    stop(sprintf("Errors adding %d keys", nerr))
  }

  if (length(dir(path_req, all.files=TRUE, no..=TRUE)) == 0L) {
    file.remove(path_req)
  }
}

##' @export
##' @rdname data_admin
data_admin_list_requests <- function(path_data=".") {
  data_check_path_data(path_data)
  data_pubs_load(data_path_request(path_data))
}
##' @export
##' @rdname data_admin
data_admin_list_keys <- function(path_data=".") {
  data_check_path_data(path_data)
  data_pubs_load(data_path_encryptr(path_data))
}

##' User commands
##' @title User commands
##'
##' @param path_data Path to the data.  The default is the current
##'   working directory.
##'
##' @param path_user Path to the directory with your user key.
##'   Usually this can be ommited.  Use the \code{encryptr.user.path}
##'   global option (i.e., via \code{options()}) to set this more
##'   conveniently.
##'
##' @param quiet Suppress printing of informative messages.
##'
##' @export
##' @rdname data_user
data_request_access <- function(path_data=".", path_user=NULL, quiet=FALSE) {
  key <- data_check_path_user(path_user, quiet)
  data_check_path_data(path_data)

  ## TODO: Here, we should construct a reasonable request.  Previously
  ## I saved a little metadata with the key:
  info <- Sys.info()
  dat <- list(user=info[["user"]],
              host=info[["nodename"]],
              date=as.character(Sys.time()),
              pub=key$pub)
  hash <- openssl_fingerprint(key$pub)

  ## OK, this is a nasty and unexpected surprise;
  ##   file.copy(<directory_path>, <full_path_name>)
  ## will create an empty executable file in the destination. Wat.
  dat$signature <- openssl::signature_create(data_key_prep(dat), key=key$key)
  path_req <- data_path_request(path_data)
  dir.create(path_req, FALSE)

  dest <- file.path(path_req, bin2str(hash, ""))
  if (file.exists(dest)) {
    message("Request is already pending")
  } else {
    data_key_save(dat, dest)
  }

  ## The idea here is that they will email or whatever creating a
  ## second line of communication.  Probably this should provide a
  ## hash of the request to the validity of the request can be
  ## checked.  But I'm not really anticipating attacks here.
  ##
  ## Consider taking same approach as whoami, but falling back on
  ## asking instead?
  workflow_log(
    quiet,
    "A request has been added.  Email someone with access to add you.")
  workflow_log(quiet, paste0("\thash: ", bin2str(hash, ":")))
  if (using_git(path_data)) {
    msg <- c("If you are using git, you will need to commit and push first:",
             paste("    git add", dest),
             '    git commit -m "Please add me to the dataset"',
             '    git push')
    workflow_log(quiet, paste(msg, collapse="\n"))
  }
  invisible(hash)
}

##' @export
##' @param test Test that the encryption is working?  (Recommended)
##' @rdname data_user
config_data <- function(path_data=".", path_user=NULL, test=TRUE, quiet=FALSE) {
  x <- config_sodium_symmetric(data_load_sym(path_data, path_user, quiet))
  data_test_config(x, path_data, test)
  x
}

## Here, key is the data key encrypted with the user's public key.
## Add that to the publicly readable data.
##
## NOTE: Because the logic around overwriting is hard, this will
## overwrite without warning or notice.
data_authorise_write <- function(path_data, sym, dat, yes=FALSE, quiet=FALSE) {
  workflow_log(quiet, "Authorising %s", as.character(dat))
  if (!(yes || prompt_confirm())) {
    msg <- paste("Cancelled adding key ", bin2str((dat$hash)))
    e <- structure(list(message=msg, call=NULL),
                   class=c("cancel_addition", "error", "condition"))
    stop(e)
  }
  dat$key <- encrypt_data(sym, NULL, dat$pair)
  path_enc <- data_path_encryptr(path_data)
  hash_str <- bin2str(openssl_fingerprint(dat$pub), "")

  data_key_save(dat, file.path(path_enc, hash_str))

  file.remove(dat$filename)
  invisible()
}

data_check_path_data <- function(path_data, fail=TRUE) {
  ok <- file.exists(data_filename_test(path_data))
  if (fail && !ok) {
    stop("encryptr not set up for ", path_data)
  }
  invisible(ok)
}

data_check_path_user <- function(user, quiet=FALSE) {
  if (inherits(user, "rsa_pair")) {
    return(user)
  }
  user <- data_path_user(user)
  workflow_log(quiet, "Loading user key from %s", user)
  load_key_openssl(user, TRUE)
}

## TODO: data_pub_load changes name I think, because this is more than
## the public key now?
data_pub_load <- function(hash, path) {
  if (is.raw(hash)) {
    hash_str <- bin2str(hash, "")
  } else {
    hash_str <- gsub(":", "", hash)
    hash <- str2bin(hash_str)
  }
  filename <- file.path(path, hash_str)
  if (!file.exists(filename)) {
    stop(sprintf("No key %s found at path %s", hash, path), call.=FALSE)
  }
  dat <- readRDS(filename)

  ## Two attempts at verifying the data provided as a key to detect
  ## tampering.
  if (!identical(as.raw(openssl_fingerprint(dat$pub)), as.raw(hash))) {
    stop("Public key hash disagrees for: ", hash_str)
  }

  tryCatch(
    openssl::signature_verify(data_key_prep(dat), dat$signature, pubkey=dat$pub),
    error=function(e) stop("Signature of data does not match for ", hash_str))

  dat$pair <- load_key_openssl(dat$pub, FALSE)
  dat$filename <- filename
  class(dat) <- "data_key"
  dat
}

data_pubs_load <- function(path) {
  hash <- sub("\\.pub$", "", dir(path, pattern="^[[:xdigit:]]{32}$"))
  dat <- lapply(hash, data_pub_load, path)
  names(dat) <- hash
  class(dat) <- "data_keys"
  dat
}

data_hash <- function(x) {
  if (is.character(x)) {
    x <- read_binary(x)
  }
  sodium::hash(x, size=16L)
}

##' @export
as.character.data_key <- function(x, ..., indent="") {
  hash <- bin2str(openssl_fingerprint(x$pub), ":")
  x <- unlist(x[c("user", "host", "date")])
  sprintf("%s%s\n%s", indent, bin2str(hash),
          paste(sprintf("%s  %4s: %s",
                        indent, names(x), unlist(x)), collapse="\n"))
}

##' @export
print.data_keys <- function(x, ...) {
  if (length(x) == 0L) {
    cat("(empty)\n")
  } else {
    cat(sprintf("%d key%s:\n", length(x), ngettext(length(x), "", "s")))
    cat(paste0(vapply(x, as.character, character(1), indent="  "),
               "\n", collapse=""))
  }
  invisible(x)
}

## Some directories:
data_path_user <- function(path) {
  if (is.null(path)) {
    path <- getOption("encryptr.user.path", NULL)
  }
  find_key_openssl(path, FALSE)$pub
}

data_path_encryptr <- function(path) {
  file.path(path, ".encryptr")
}
data_path_request <- function(path_data) {
  file.path(data_path_encryptr(path_data), "requests")
}

## Some filename patterns:
data_filename_test <- function(path_data) {
  file.path(data_path_encryptr(path_data), "test")
}

data_load_sym <- function(path_data, path_user, quiet) {
  data_check_path_data(path_data)
  path_enc <- data_path_encryptr(path_data)
  key <- data_check_path_user(path_user, quiet)
  hash_str <- bin2str(openssl_fingerprint(key$pub), "")
  path_data_key <- file.path(path_enc, hash_str)
  if (!file.exists(path_data_key)) {
    data_access_error(path_data, path_user, path_data_key)
  }
  sym <- decrypt_data(readRDS(path_data_key)$key, NULL, key)
  load_key_sodium_symmetric(sym)
}

data_access_error <- function(path_data, path_user, path_data_key) {
  ## TODO: Try to guess the path used; this is really annoying because
  ## sometimes we have a key and sometimes a path, but I do not
  ## remember when we just get the public key (which causes an issue
  ## here).
  cmd <- call("data_request_access", path_data)
  cmd <- paste(deparse(cmd, getOption("width", 60L)), collapse="\n")
  msg <- paste(c("Key file not found; you may not have access",
                 sprintf("(looked in %s)", path_data_key),
                 paste0("To request access, run:\n  ", cmd)),
               collapse="\n")
  stop(msg, call.=FALSE)
}

data_test_config <- function(x, path_data, test) {
  if (test) {
    res <- try(decrypt(readLines(data_filename_test(path_data)), x))
    if (!identical(res, "encryptr")) {
      stop("Decryption failed")
    }
  }
}

workflow_log <- function(quiet, ...) {
  if (!quiet) {
    message(sprintf(...))
  }
}

data_key_prep <- function(x) {
  serialize(unclass(x[c("user", "host", "date", "pub")]), NULL)
}
data_key_save <- function(x, filename) {
  keep <- c("user", "host", "date", "pub", "signature", "key")
  saveRDS(x[names(x) %in% keep], filename)
}
