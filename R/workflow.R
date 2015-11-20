## NOTE: All functions here are arbitrarily prefixed with 'data'
## because they're the 'data workflow' part of the package.  I may
## move them elsewhere.
##
## It does make me wish there was some easy way (i.e., not local) of
## having namespaces that are file specific...

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
##'   things in a hidden directory within this path.
##'
##' @param path_user Path to the directory with your user key.
##'   Usually this can be ommited.
##'
##' @param quiet Suppress printing of informative messages.
##' @export
##' @rdname data_admin
data_admin_init <- function(path_data, path_user=NULL, quiet=FALSE) {
  if (!is_directory(path_data)) {
    stop("path_data must exist and be a directory")
  }
  path_enc <- data_path_encryptr(path_data)
  if (!data_check_path_data(path_data, fail=FALSE)) {
    if (!quiet) {
      message("Generating data key")
    }
    dir.create(path_enc, FALSE)

    ## Now, the idea is to create a key for the data set:
    sym <- sodium::keygen()

    ## NOTE: If anything below fails, this file needs deleting, as
    ## this is the file that we check to see if things are set up
    ## correctly (data_check_path_data()).
    path_test <- data_filename_test(path_data)
    encrypt(writeLines("encryptr", path_test),
            config_symmetric(sym))
    on.exit(file.remove(path_test))

    if (!quiet) {
      message("Authorising ourselves")
    }

    ## Now, make a copy of the public key; probably what needs to
    ## happen here is that we authorise ourselves but this case is a
    ## little different because we already have the symmetric key.
    ## But this bit is shared; we need to copy the files around a
    ## bunch.
    tmp <- data_request_access(path_data, path_user, quiet=TRUE)
    ## NOTE: here we can't use data_admin_authorise because we can't
    ## load the symmetric key from the files we're trying to write!
    dat <- data_pub_load(tmp, data_path_request(path_data))
    key <- sodium::simple_encrypt(sym, dat$pub)
    data_authorise_write(path_data, key, dat, quiet)
  } else {
    if (!quiet) {
      message("Already set up")
    }
  }

  if (!quiet) {
    message("Verifying")
  }
  x <- config_data(path_data, path_user, TRUE)
  on.exit()
  invisible(TRUE)
}

##' @export
##' @rdname data_admin
##'
##' @param hash The hash of a key to add.  Use
##'   \code{data_admin_list_requests} to see hashes of pending requests.
data_admin_authorise <- function(hash, path_data, path_user=NULL, quiet=FALSE) {
  ## TODO: allow prompting.
  data_check_path_data(path_data)
  path_user <- data_path_user(path_user)
  dat <- data_pub_load(hash, data_path_request(path_data))
  key <- sodium::simple_encrypt(data_load_sym(path_data, path_user), dat$pub)
  data_authorise_write(path_data, key, dat, quiet)
}

##' @export
##' @rdname data_admin
data_admin_list_requests <- function(path_data) {
  data_check_path_data(path_data)
  data_pubs_load(data_path_request(path_data))
}
##' @export
##' @rdname data_admin
data_admin_list_keys <- function(path_data) {
  data_check_path_data(path_data)
  data_pubs_load(data_path_encryptr(path_data))
}

##' User commands
##' @title User commands
##'
##' @param password What do we do about passwords?  Options are
##'   \code{FALSE} for no password, \code{TRUE} for prompting for a
##'   password, or a string value for a password (which will end up in
##'   things like your history so be careful).
##'
##' @param path Path to the directory with your user key.  Usually
##'   this can be ommited.  Use the \code{encryptr.user.path} global
##'   option (i.e., via \code{options()}) to set this more
##'   conveniently.
##'
##' @param quiet Suppress printing of informative messages.
##' @export
##' @rdname data_user
data_user_init <- function(password=FALSE, path=NULL, quiet=FALSE) {
  create_keypair(data_path_user(path), password, quiet, "id_encryptr")
}

##' @export
##' @param path_data Path to the data
##' @rdname data_user
data_request_access <- function(path_data, path=NULL, quiet=FALSE) {
  ## TODO: If the admin part set an email address then we could
  ## automatically email the right person; that'd be cool.
  ##
  ## TODO: If a request is already pending we should not do anything.
  data_check_path_data(path_data)
  ## TODO: Consider whether running this is OK; perhaps a flag to
  ## indicate how this is being run and refuse to create keys if
  ## running noninteractively and implicitly.  Similarly, need to
  ## consider how things like passwords are going to be treated.
  path_pub <- data_user_init(path=path)
  path_req <- data_path_request(path_data)
  dir.create(path_req, FALSE)

  hash <- data_hash(path_pub)
  file.copy(path_pub,
            filename_pub(path_req, bin2str(hash, "")))

  ## The idea here is that they will email or whatever creating a
  ## second line of communication.  Probably this should provide a
  ## hash of the request to the validity of the request can be
  ## checked.  But I'm not really anticipating attacks here.
  ##
  ## If full names or email addresses are added to the existing files
  ## then it would be straightforward to read through and get a set of
  ## people to contact (TODO).
  ##
  ## Consider taking same approach as whoami, but falling back on
  ## asking instead?
  if (!quiet) {
    message("A request has been added.  Email someone with access to add you.")
    message("\thash: ", bin2str(hash))
  }
  invisible(hash)
}

##' @export
##' @param test Test that the encryption is working?  (Recommended)
##' @rdname data_user
config_data <- function(path_data, path=NULL, test=TRUE) {
  x <- config_symmetric(data_load_sym(path_data, path))
  data_test_config(x, path_data, test)
  x
}

##' Read a public key
##' @title Read a public key
##'
##' @param path Either \code{NULL} or a directory name to read your
##'   public key, or a full filename of a file to read a different
##'   key.
##'
##' @export
data_key_read <- function(path=NULL) {
  read_public_key(data_path_user(path))
}

## Here, key is the key encrypted with the user's public key.
## TODO: check destination path does not exist so we don't replace things.
## TODO: add support for y/n checking here (e.g., package:ask)
data_authorise_write <- function(path_data, key, dat, quiet=FALSE) {
  if (!quiet) {
    message(paste0("Authorising ", as.character(dat)))
  }
  path_enc <- data_path_encryptr(path_data)
  hash_str <- bin2str(dat$hash, "")
  writeBin(key, filename_key(path_enc, hash_str))
  file.copy(dat$filename, filename_pub(path_enc, hash_str))
  file.remove(dat$filename)
  invisible(dat$hash)
}

data_check_path_data <- function(path_data, fail=TRUE) {
  ok <- file.exists(data_filename_test(path_data))
  if (fail && !ok) {
    stop("encryptr not set up for ", path_data)
  }
  invisible(ok)
}

data_pub_load <- function(hash, path) {
  if (is.raw(hash)) {
    hash_str <- bin2str(hash, "")
  } else {
    hash_str <- gsub(":", "", hash)
    hash <- str2bin(hash_str)
  }
  filename <- filename_pub(path, hash_str)
  if (!identical(data_hash(filename), hash)) {
    stop("Hash disagrees for: ", hash_str)
  }
  read_public_key(filename)
}

data_pubs_load <- function(path) {
  files <- dir(path, pattern="^[[:xdigit:]]{32}\\.pub$")
  dat <- lapply(sub(".pub$", "", files), data_pub_load, path)
  names(dat) <- vapply(dat, function(x) bin2str(x$hash), character(1))
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
print.data_keys <- function(x, ...) {
  if (length(x) == 0L) {
    cat("(empty)\n")
  } else {
    cat(paste0(vapply(x, as.character, character(1)), "\n", collapse="\n"))
  }
  invisible(x)
}

## Some directories:
data_path_user <- function(path) {
  ##   * if given a path we'll take that
  ##   * if encryptr.path is set we'll take that
  ##   * otherwise fall back on rappdirs to find us somewhere sensible
  if (is.null(path)) {
    getOption("encryptr.user.path", rappdirs::user_data_dir("encryptr"))
  } else {
    path
  }
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

data_load_sym <- function(path_data, path_user) {
  data_check_path_data(path_data)
  path_enc <- data_path_encryptr(path_data)
  path_user <- data_path_user(path_user)
  hash <- data_hash(filename_pub(path_user))
  path_data_key <- filename_key(path_enc, bin2str(hash, ""))
  if (!file.exists(path_data_key)) {
    data_access_error(path_data, path_user, path_data_key)
  }
  sodium::simple_decrypt(read_binary(path_data_key),
                         read_private_key(path_user))
}

data_access_error <- function(path_data, path_user, path_data_key) {
  if (identical(data_path_user(NULL), path_user)) {
    cmd <- call("data_request_access", path_data)
  } else {
    cmd <- call("data_request_access", path_data, path_user)
  }
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
