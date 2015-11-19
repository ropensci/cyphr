## NOTE: All functions here are arbitrarily prefixed with 'data'
## because they're the 'data workflow' part of the package.  I may
## move them elsewhere.

## Where to look for user keys:
##
##   * if given a path we'll take that
##   * if encryptr.path is set we'll take that
##   * otherwise fall back on rappdirs to find us somewhere sensible
data_encryptr_user_path <- function(path) {
  if (is.null(path)) {
    getOption("encryptr.path", rappdirs::user_data_dir("encryptr"))
  } else {
    path
  }
}

## In addition to the key, people need to *decribe* the key.
##
## We'll save three files:
##   * machine readable private key
##   * machine readable public key
##   * human readable public key with some metadata
data_user_setup <- function(path=NULL, quiet=FALSE) {
  path <- data_encryptr_user_path(path)
  path_txt <- filename_txt(path)
  if (!file.exists(path_txt)) {
    if (!quiet) {
      message("Creating public key in ", path_txt)
    }
    dir.create(path, FALSE, TRUE)
    path_key <- filename_key(path)
    path_pub <- filename_pub(path)
    key <- sodium::keygen()
    pub <- sodium::pubkey(key)
    writeBin(key, path_key)
    writeBin(pub, path_pub)
    ## Not sure if this is always supported:
    Sys.chmod(path_key, "600")

    ## Collect metadata:
    info <- Sys.info()
    dat <- list(user=info[["user"]],
                host=info[["nodename"]],
                date=as.character(Sys.time()),
                pub=bin2str(pub))
    write.dcf(dat, path_txt, width=500)
  }
  invisible(path_txt)
}

data_admin_setup <- function(path_data, path=NULL, quiet=FALSE) {
  if (!is_directory(path_data)) {
    stop("path_data must exist and be a directory")
  }
  path_enc <- filename_encryptr(path_data)
  path_test <- filename_test(path_data)

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
    tmp <- data_request_access(path_data, path, quiet=TRUE)
    dat <- data_key_load(bin2str(tmp), filename_request(path_data))
    key <- sodium::simple_encrypt(sym, dat$pub)
    data_authorise_write(path_data, key, dat, quiet)
  } else {
    if (!quiet) {
      message("Already set up")
    }
  }

  ## Verify that things are OK:
  x <- data_config(path_data, path, TRUE)
  on.exit()
  invisible(TRUE)
}

## Here, key is the key encrypted with the user's public key.
## TODO: check destination path does not exist so we don't replace things.
## TODO: add support for y/n checking here (e.g., package:ask)
data_authorise_write <- function(path_data, key, dat, quiet=FALSE) {
  if (!quiet) {
    message(paste0("Authorising ", as_character_key(dat)))
  }

  path_enc <- filename_encryptr(path_data)
  hash_str <- bin2str(dat$hash, "")
  writeBin(key, filename_key(path_enc, hash_str))
  file.copy(dat$filename, file.path(path_enc, hash_str))
  file.remove(dat$filename)
  invisible(dat$hash)
}

data_config <- function(path_data, path=NULL, test=FALSE) {
  x <- config_symmetric(data_load_sym(path_data, path))
  data_test_config(x, path_data, test)
  x
}

data_check_path_data <- function(path_data) {
  if (!file.exists(filename_test(path_data))) {
    stop("encryptr not set up for ", path_data)
  }
}

## TODO: If the admin part set an email address then we could
## automatically email the right person; that'd be cool.
data_request_access <- function(path_data, path=NULL, quiet=FALSE) {
  data_check_path_data(path_data)
  path_txt <- data_user_setup(path)
  path_req <- filename_request(path_data)
  dir.create(path_req, FALSE)

  ## TODO: here, should probably check that pub and txt agree on public key.
  ## TODO: not 100% sure if I should be using sig_sign instead?
  dat <- read_binary(filename_txt(path))
  hash <- data_hash(dat)
  writeBin(dat, file.path(path_req, bin2str(hash, "")))

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

data_key_read <- function(filename) {
  dat <- as.list(read.dcf(filename)[1, ])
  dat$pub <- sodium::hex2bin(dat$pub)
  dat
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
  ret <- data_key_read(filename)
  ret$filename <- filename
  ret$hash <- str2bin(hash)
  ret
}

data_keys_load <- function(path) {
  files <- dir(path, pattern="^[[:xdigit:]]{32}$")
  structure(lapply(files, data_key_load, path),
            names=files,
            class="data_keys")
}

data_admin_requests <- function(path_data) {
  data_check_path_data(path_data)
  data_keys_load(filename_request(path_data))
}
data_admin_keys <- function(path_data) {
  data_check_path_data(path_data)
  data_keys_load(filename_encryptr(path_data))
}

data_hash <- function(x) {
  if (is.character(x)) {
    x <- read_binary(x)
  }
  sodium::hash(x, size=16L)
}

##' @export
print.data_keys <- function(x, ...) {
  cat(paste0(vapply(x, as_character_key, character(1)), "\n", collapse="\n"))
  invisible(x)
}

## Might become an s3 method:
as_character_key <- function(x) {
  v <- c("user", "host", "date", "pub")
  x$pub <- bin2str(x$pub)
  x$hash <- bin2str(x$hash)
  sprintf("%s:\n%s", bin2str(x$hash),
          paste(sprintf("  %4s: %s", v, unlist(x[v])), collapse="\n"))
}

data_admin_authorise <- function(hash, path_data, path=NULL, quiet=FALSE) {
  data_check_path_data(path_data)
  path <- data_encryptr_user_path(path)
  dat <- data_key_load(hash, filename_request(path_data))
  key <- sodium::simple_encrypt(data_load_sym(path_data, path), dat$pub)
  data_authorise_write(path_data, key, dat, quiet)
}

filename_pub <- function(path, name="id_encryptr") {
  paste0(file.path(path, name), ".pub")
}
filename_key <- function(path, name="id_encryptr") {
  paste0(file.path(path, name), ".key")
}
filename_txt <- function(path, name="id_encryptr") {
  paste0(file.path(path, name), ".txt")
}
filename_encryptr <- function(path) {
  file.path(path, ".encryptr")
}
filename_test <- function(path_data) {
  file.path(filename_encryptr(path_data), "test")
}
filename_request <- function(path_data) {
  file.path(filename_encryptr(path_data), "requests")
}


## Attempt to make a backup key.  This key will be stored in plain
## sight but the passphrase will be prompted for.
data_password_make_key <- function(filename, path_data, path=NULL) {
  res <- sodium::data_encrypt(data_load_sym(path_data, path),
                              get_password(TRUE))
  writeBin(add_nonce(res), filename)
  invisible(filename)
}

data_load_sym <- function(path_data, path) {
  ## TODO: have data_check_path_data return the correct path (path_enc)
  data_check_path_data(path_data)
  path <- data_encryptr_user_path(path)
  path_enc <- filename_encryptr(path_data)
  hash <- data_hash(filename_txt(path))
  path_data_key <- filename_key(path_enc, bin2str(hash, ""))
  if (!file.exists(path_data_key)) {
    stop("Key file not found: ", path_data_key)
  }
  sodium::simple_decrypt(read_binary(path_data_key),
                         read_binary(filename_key(path)))
}

config_password <- function(filename, path_data, test=FALSE) {
  x <- config_symmetric(
    sodium::data_decrypt(split_nonce(read_binary(filename)),
                         get_password(FALSE)))
  data_test_config(x, path_data, test)
  x
}

data_test_config <- function(x, path_data, test) {
  if (test) {
    res <- try(decrypt(readLines(filename_test(path_data)), x))
    if (!identical(res, "encryptr")) {
      stop("Decryption failed")
    }
  }
}
