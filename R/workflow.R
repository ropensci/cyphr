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
  path_test <- data_filename_test(path_data)

  if (!file.exists(path_test)) {
    if (!quiet) {
      message("Generating data key")
    }
    dir.create(path_enc, FALSE)

    ## Now, the idea is to create a key for the data set:
    sym <- sodium::keygen()

    ## TODO: If anything below fails, this file needs deleting.
    ## Otherwise the various checks will get confused!  Alternatively,
    ## test for the existance of the .encryptr directory rather than
    ## the test file.
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
    dat <- data_key_load(bin2str(tmp), data_path_request(path_data))
    key <- sodium::simple_encrypt(sym, dat$pub)
    data_authorise_write(path_data, key, dat, quiet)
  } else {
    ## TODO: this should do something different in the case where a
    ## different user tries to run init.  The current message/error
    ## situation might be ok though.
    if (!quiet) {
      message("Already set up")
    }
  }

  ## Verify that things are OK:
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
  path_user <- data_user_path(path_user)
  dat <- data_key_load(hash, data_path_request(path_data))
  key <- sodium::simple_encrypt(data_load_sym(path_data, path_user), dat$pub)
  data_authorise_write(path_data, key, dat, quiet)
}

##' @export
##' @rdname data_admin
data_admin_list_requests <- function(path_data) {
  data_check_path_data(path_data)
  data_keys_load(data_path_request(path_data))
}
##' @export
##' @rdname data_admin
data_admin_list_keys <- function(path_data) {
  data_check_path_data(path_data)
  data_keys_load(data_path_encryptr(path_data))
}

## NOTE: All functions here are arbitrarily prefixed with 'data'
## because they're the 'data workflow' part of the package.  I may
## move them elsewhere.
##
## It does make me wish there was some easy way (i.e., not local) of
## having namespaces that are file specific...

## Where to look for user keys:
##
##   * if given a path we'll take that
##   * if encryptr.path is set we'll take that
##   * otherwise fall back on rappdirs to find us somewhere sensible
data_user_path <- function(path) {
  if (is.null(path)) {
    getOption("encryptr.user.path", rappdirs::user_data_dir("encryptr"))
  } else {
    path
  }
}
##' User commands
##' @title User commands
##'
##' @param path Path to the directory with your user key.  Usually
##'   this can be ommited.  Use the \code{encryptr.user.path} global
##'   option (i.e., via \code{options()}) to set this more
##'   conveniently.
##'
##' @param quiet Suppress printing of informative messages.
##' @export
##' @rdname data_user
data_user_init <- function(path=NULL, quiet=FALSE) {
  path <- data_user_path(path)
  path_pub <- data_filename_pub(path)
  if (!file.exists(path_pub)) {
    if (!quiet) {
      message("Creating public key in ", path_pub)
    }
    dir.create(path, FALSE, TRUE)
    path_key <- data_filename_key(path)
    key <- sodium::keygen()
    pub <- sodium::pubkey(key)
    writeBin(key, path_key)
    ## Not sure if this is always supported:
    Sys.chmod(path_key, "600")

    ## Collect metadata:
    info <- Sys.info()
    dat <- list(user=info[["user"]],
                host=info[["nodename"]],
                date=as.character(Sys.time()),
                pub=bin2str(pub))
    write.dcf(dat, path_pub, width=500)
  }
  invisible(path_pub)
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
  path_pub <- data_user_init(path)
  path_req <- data_path_request(path_data)
  dir.create(path_req, FALSE)

  ## TODO: not 100% sure if I should be using sig_sign instead?
  hash <- data_key_hash(path)
  writeBin(read_binary(path_pub),
           file.path(path_req, bin2str(hash, "")))

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
    message("A request has been added.  Email somone with access to add you.")
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
  if (is.null(path)) {
    path <- data_filename_pub(data_user_path(path))
  } else if (is_directory(path)) {
    path <- data_filename_pub(path)
  }
  dat <- as.list(read.dcf(path)[1, ])
  dat$pub <- sodium::hex2bin(dat$pub)
  dat$hash <- data_hash(path)
  dat$filename <- path
  class(dat) <- "data_key"
  dat
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
  writeBin(key, data_filename_key(path_enc, hash_str))
  file.copy(dat$filename, file.path(path_enc, hash_str))
  file.remove(dat$filename)
  invisible(dat$hash)
}

data_check_path_data <- function(path_data) {
  path_enc <- data_path_encryptr(path_data)
  if (!file.exists(path_enc)) {
    stop("encryptr not set up for ", path_data)
  }
  invisible(path_enc)
}

## User level:
## * data_request_access
## * data_key_read
## * data_key_hash?

## TODO: harmonise with data_key_read so that when called with no
## arguments both have this behaviour and load the user key.
data_key_hash <- function(path=NULL) {
  path <- data_user_path(path)
  filename <- data_filename_pub(path)
  data_hash(filename)
}

data_key_load <- function(hash, path) {
  if (is.raw(hash)) {
    hash <- bin2str(hash, "")
  } else {
    hash <- gsub(":", "", hash)
  }
  filename <- file.path(path, hash)
  if (!identical(data_hash(filename), str2bin(hash))) {
    stop("Hash disagrees for: ", hash)
  }
  data_key_read(filename)
}

data_keys_load <- function(path) {
  files <- dir(path, pattern="^[[:xdigit:]]{32}$")
  nms <- vapply(files, function(x) bin2str(str2bin(x)), character(1),
                USE.NAMES=FALSE)
  structure(lapply(files, data_key_load, path),
            names=nms,
            class="data_keys")
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
    cat("(no requests)\n")
  } else {
    cat(paste0(vapply(x, as.character, character(1)), "\n", collapse="\n"))
  }
  invisible(x)
}

##' @export
print.data_key <- function(x, ...) {
  cat(as.character(x), "\n", sep="")
}
##' @export
as.character.data_key <- function(x, ...) {
  v <- c("user", "host", "date", "pub")
  x$pub <- bin2str(x$pub)
  x$hash <- bin2str(x$hash)
  sprintf("%s:\n%s", bin2str(x$hash),
          paste(sprintf("  %4s: %s", v, unlist(x[v])), collapse="\n"))
}

## Some directories:
data_path_encryptr <- function(path) {
  file.path(path, ".encryptr")
}
data_path_request <- function(path_data) {
  file.path(data_path_encryptr(path_data), "requests")
}

## Some filename patterns:
data_filename_key <- function(path, name="id_encryptr") {
  paste0(file.path(path, name), ".key")
}
data_filename_pub <- function(path, name="id_encryptr") {
  paste0(file.path(path, name), ".pub")
}
data_filename_test <- function(path_data) {
  file.path(data_path_encryptr(path_data), "test")
}

data_load_sym <- function(path_data, path) {
  ## TODO: have data_check_path_data return the correct path (path_enc)
  path_enc <- data_check_path_data(path_data)
  path <- data_user_path(path)
  hash <- data_key_hash(path)
  path_data_key <- data_filename_key(path_enc, bin2str(hash, ""))
  if (!file.exists(path_data_key)) {
    stop("Key file not found: ", path_data_key)
  }
  sodium::simple_decrypt(read_binary(path_data_key),
                         read_binary(data_filename_key(path)))
}

data_test_config <- function(x, path_data, test) {
  if (test) {
    res <- try(decrypt(readLines(data_filename_test(path_data)), x))
    if (!identical(res, "encryptr")) {
      stop("Decryption failed")
    }
  }
}

## Attempt to make a backup key.  This key will be stored in plain
## sight but the passphrase will be prompted for.
data_password_make_key <- function(filename, path_data, path=NULL) {
  res <- sodium::data_encrypt(data_load_sym(path_data, path),
                              get_password(TRUE))
  writeBin(add_nonce(res), filename)
  invisible(filename)
}
config_password <- function(filename, path_data, test=FALSE) {
  x <- config_symmetric(
    sodium::data_decrypt(split_nonce(read_binary(filename)),
                         get_password(FALSE)))
  data_test_config(x, path_data, test)
  x
}
