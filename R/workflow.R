## NOTE: All functions here are arbitrarily prefixed with 'data'
## because they're the 'data workflow' part of the package.  I may
## move them elsewhere.
##
## It does make me wish there was some easy way (i.e., not local) of
## having namespaces that are file specific...
##
## TODO: The encryption here feels clumsy; I'd rather remove all of
## the $encrypt and $decrypt calls, all uses of pack_data and
## unpack_data in favour of more general encryption + IO functions.

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
    sym <- key_sodium_symmetric(sodium::keygen())

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
    ## TODO: We should pass in the key here:
    tmp <- data_request_access(path_data, key, quiet=TRUE)
    ## NOTE: here we can't use data_admin_authorise because we can't
    ## load the symmetric key from the files we're trying to write!
    dat <- data_pub_load(tmp, data_path_request(path_data))
    data_authorise_write(path_data, sym, dat, TRUE, quiet)
  } else {
    workflow_log(quiet, "Already set up")
  }

  workflow_log(quiet, "Verifying")
  ## TODO: pass in key as path+user.
  x <- config_data(path_data, key, TRUE)
  on.exit()
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
  } else {
    stop("Not yet implemented")
  }

  if (length(keys) == 0L) {
    workflow_log(quiet, "No keys to add")
  }

  ## This is the point where we'd be asked for a password.  Perhaps
  ## don't run this if there are no requests?
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
    if (FALSE && using_git(path_data)) {
      ## TODO: This needs fixing; but that depends on getting the
      ## payload correct.
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
##'
##' @export
##' @param path_data Path to the data.  The default is the current
##'   working directory.
##'
##' @rdname data_user
data_request_access <- function(path_data=".", path_user=NULL, quiet=FALSE) {
  data_check_path_data(path_data)
  path_req <- data_path_request(path_data)

  if (is.character(path_user)) {
    key <- data_check_path_user(path_user, quiet)
  } else if (inherits(path_user, "rsa_pair")) {
    key <- path_user
  } else {
    stop("Expected a path or a rsa_pair object")
  }
  path_pub <- key$path_pub
  dir.create(path_req, FALSE)
  hash <- data_hash(key$path_pub)

  ## OK, this is a nasty and unexpected surprise;
  ##   file.copy(<directory_path>, <full_path_name>)
  ## will create an empty executable file in the destination. Wat.
  dest <- TMP_filename_key(path_req, bin2str(hash, ""), TRUE)
  if (file.exists(dest)) {
    message("Request is already pending")
  } else {
    file.copy(key$path_pub, dest)
  }

  ## The idea here is that they will email or whatever creating a
  ## second line of communication.  Probably this should provide a
  ## hash of the request to the validity of the request can be
  ## checked.  But I'm not really anticipating attacks here.
  ##
  ## Consider taking same approach as whoami, but falling back on
  ## asking instead?
  if (!quiet) {
    message("A request has been added.  Email someone with access to add you.")
    message("\thash: ", bin2str(hash, ":"))
    if (using_git(path_data)) {
      msg <- c("If you are using git, you will need to commit and push first:",
               paste("    git add", dest),
               '    git commit -m "Please add me to the dataset"',
               '    git push')
      message(paste(msg, collapse="\n"))
    }
  }
  invisible(hash)
}

##' @export
##' @param test Test that the encryption is working?  (Recommended)
##' @rdname data_user
config_data <- function(path_data=".", path=NULL, test=TRUE, quiet=FALSE) {
  x <- config_symmetric(data_load_sym(path_data, path, quiet))
  data_test_config(x, path_data, test)
  x
}

## Here, key is the data key encrypted with the user's public key.
##
## NOTE: Because the logic around overwriting is hard, this will
## overwrite without warning or notice.
data_authorise_write <- function(path_data, sym, dat, yes=FALSE, quiet=FALSE) {
  if (!quiet) {
    message(paste0("Authorising ", as_character(dat$pub), collapse="\n"))
  }
  if (!(yes || prompt_confirm())) {
    msg <- paste("Cancelled adding key ", bin2str((dat$hash)))
    e <- structure(list(message=msg, call=NULL),
                   class=c("cancel_addition", "error", "condition"))
    stop(e)
  }
  path_enc <- data_path_encryptr(path_data)
  hash_str <- bin2str(data_hash(dat$path_pub), "")
  writeBin(pack_data(make_config(dat)$encrypt(sym)),
           TMP_filename_key(path_enc, hash_str, FALSE))
  file.copy(dat$path_pub,
            TMP_filename_key(path_enc, hash_str), TRUE)
  file.remove(dat$path_pub)
  invisible()
}

data_check_path_data <- function(path_data, fail=TRUE) {
  ok <- file.exists(data_filename_test(path_data))
  if (fail && !ok) {
    stop("encryptr not set up for ", path_data)
  }
  invisible(ok)
}

data_check_path_user <- function(user, quiet) {
  if (inherits(user, "rsa_pair")) {
    return(user)
  }
  user <- data_path_user(user)
  workflow_log(quiet, "Loading key from %s", user)
  load_key_rsa(user, NULL)
}

data_pub_load <- function(hash, path) {
  if (is.raw(hash)) {
    hash_str <- bin2str(hash, "")
  } else {
    hash_str <- gsub(":", "", hash)
    hash <- str2bin(hash_str)
  }
  filename <- TMP_filename_key(path, hash_str, TRUE)
  if (!identical(data_hash(filename), hash)) {
    stop("Hash disagrees for: ", hash_str)
  }

  load_key_rsa(filename, FALSE)
}

data_pubs_load <- function(path) {
  hash <- sub("\\.pub$", "", dir(path, pattern="^[[:xdigit:]]{32}\\.pub$"))
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
print.data_keys <- function(x, ...) {
  if (length(x) == 0L) {
    cat("(empty)\n")
  } else {
    ## TODO: I don't like how the hash I use here is different to the
    ## fingerprint hash used by Jeroen; I do need to swap that out.
    cat(sprintf("%d keys\n", length(x)))
  }
  invisible(x)
}

## Some directories:
data_path_user <- function(path) {
  ##   * if given a path we'll take that
  ##   * if encryptr.path is set we'll take that
  ##   * otherwise fall back on the USER_KEY environment variable
  ##   * otherwise fall back on ~/.ssh/id_rsa if it exists
  ##   * otherwise fail
  ##
  ## TODO: Not really clear what to do if the file is not id_rsa here;
  ## consider tweaking everything to work in terms of the path to the
  ## private key rather than the directory?
  ##
  ## TODO: This overlaps the logic in openssl quite badly.
  if (is.null(path)) {
    path <- getOption("encryptr.user.path", NULL)
    if (is.null(path)) {
      path <- Sys.getenv("OPENSSL_PATH", "")
      if (path == "") {
        if (file.exists("~/.ssh/id_rsa")) {
          path <- "~/.ssh"
        } else {
          stop("Could not determine user key path")
        }
      }
    }
  }
  path
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
  hash <- data_hash(key$path_pub)
  path_data_key <- TMP_filename_key(path_enc, bin2str(hash, ""), FALSE)
  if (!file.exists(path_data_key)) {
    data_access_error(path_data, path_user, path_data_key)
  }
  sym <- make_config(key)$decrypt(unpack_data(read_binary(path_data_key)))
  key_sodium_symmetric(sym)
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

workflow_log <- function(quiet, ...) {
  if (!quiet) {
    message(sprintf(...))
  }
}

TMP_filename_key <- function(path, base, public=TRUE) {
  file.path(path, paste0(base, if (public) ".pub" else ""))
}
