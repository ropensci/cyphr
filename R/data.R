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
##   data_admin_authorise
##   data_admin_list_requests
##   data_admin_list_keys
##   data_request_access
##   data_key
##
## with most of these being admin functions that will be used fairly
## little; the data_key one is the only one people will need to use
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
##'   things in a hidden directory within this path.
##'
##' @param path_user Path to the directory with your ssh key.
##'   Usually this can be omitted.
##'
##' @param quiet Suppress printing of informative messages.
##' @export
##' @rdname data_admin
##' @seealso \code{\link{data_request_access}} for requesting access
##'   to the data, and and \code{data_key} for using the data
##'   itself.  But for a much more thorough overview, see the vignette
##'   (\code{vignette("data", package="cyphr")}).
##' @examples
##'
##' # The workflow here does not really lend itself to an example,
##' # please see the vignette instead.
##'
##' # First we need a set of user ssh keys.  In a non example
##' # environment your personal ssh keys will probably work well, but
##' # hopefully they are password protected so cannot be used in
##' # examples.  The password = FALSE argument is only for testing,
##' # and should not be used for data that you care about.
##' path_ssh_key <- tempfile()
##' cyphr::ssh_keygen(path_ssh_key, password = FALSE)
##'
##' # Initialise the data directory, using this key path.  Ordinarily
##' # the path_user argument would not be needed because we would be
##' # using your user ssh keys:
##' path_data <- tempfile()
##' dir.create(path_data, FALSE, TRUE)
##' cyphr::data_admin_init(path_data, path_user = path_ssh_key)
##'
##' # Now you can get the data key
##' key <- cyphr::data_key(path_data, path_user = path_ssh_key)
##'
##' # And encrypt things with it
##' cyphr::encrypt_string("hello", key)
##'
##' # See the vignette for more details.  This is not the best medium
##' # to explore this.
##'
##' # Cleanup
##' unlink(path_ssh_key, recursive = TRUE)
##' unlink(path_data, recursive = TRUE)
data_admin_init <- function(path_data, path_user = NULL, quiet = FALSE) {
  pair <- data_load_keypair_user(path_user)

  if (!is_directory(path_data)) {
    stop("'path_data' must exist and be a directory")
  }
  path_cyphr <- data_path_cyphr(path_data)
  if (!data_check_path_data(path_data, fail = FALSE)) {
    workflow_log(quiet, "Generating data key")
    dir.create(path_cyphr, FALSE, TRUE)

    ## Now, the idea is to create a key for the data set:
    sym <- key_sodium(sodium::keygen())

    ## NOTE: If anything below fails, this file needs deleting, as
    ## this is the file that we check to see if things are set up
    ## correctly (data_check_path_data()).
    path_test <- data_path_test(path_data)
    encrypt_string("cyphr", sym, path_test)
    on.exit({
      workflow_log(quiet, "Removing data key")
      file.remove(path_test)
    })

    ## Just check that this all works:
    decrypt_string(path_test, sym)

    workflow_log(quiet, "Authorising ourselves")

    ## Now, make a copy of the public key; probably what needs to
    ## happen here is that we authorise ourselves but this case is a
    ## little different because we already have the symmetric key.
    ## But this bit is shared; we need to copy the files around a
    ## bunch.
    hash <- data_request_access(path_data, pair, quiet = TRUE)
    on.exit(unlink(data_path_request(path_data), recursive = TRUE),
            add = TRUE)
    ## NOTE: here we can't use data_admin_authorise because we can't
    ## load the symmetric key from the files we're trying to write!
    dat <- data_pub_load(hash, data_path_request(path_data))
    data_authorise_write(path_data, sym, dat, TRUE, quiet)
  } else {
    workflow_log(quiet, "Already set up")
  }

  workflow_log(quiet, "Verifying")
  x <- data_key(path_data, pair, TRUE)
  on.exit() # disable possible file removals.
  invisible(x)
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
data_admin_authorise <- function(path_data, hash = NULL, path_user = NULL,
                                 yes = FALSE, quiet = FALSE) {
  data_check_path_data(path_data)
  keys <- data_load_request(path_data, hash, quiet)
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
             cancel_addition = handle_cancel)
  }
  nok <- length(keys) - nerr
  if (nok > 0) {
    workflow_log(quiet, "Added %d key%s", nok, ngettext(nok, "", "s"))
    if (using_git(path_data)) {
      users <- paste(vapply(keys, function(x) x$user, character(1)),
                     collapse = ", ")
      msg <- c("If you are using git, you will need to commit and push:",
               "    git add .cyphr",
               sprintf('    git commit -m "Authorised %s"', users),
               '    git push')
      workflow_log(quiet, paste(msg, collapse = "\n"))
    }
  }
  if (nerr > 0L) {
    stop(sprintf("Errors adding %d keys", nerr))
  }

  path_req <- data_path_request(path_data)
  if (length(dir(path_req, all.files = TRUE, no.. = TRUE)) == 0L) {
    unlink(path_req, recursive = TRUE)
  }
  invisible()
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
  data_pubs_load(data_path_cyphr(path_data))
}

##' User commands
##' @title User commands
##'
##' @param path_data Path to the data
##'
##' @param path_user Path to the directory with your user key.
##'   Usually this can be omitted.  Use the \code{cyphr.user.path}
##'   global option (i.e., via \code{options()}) to set this more
##'   conveniently.
##'
##' @param quiet Suppress printing of informative messages.
##'
##' @export
##' @rdname data_user
##' @examples
##'
##' # The workflow here does not really lend itself to an example,
##' # please see the vignette.
##'
##' # Suppose that Alice has created a data directory:
##' path_alice <- tempfile()
##' cyphr::ssh_keygen(path_alice, password = FALSE)
##' path_data <- tempfile()
##' dir.create(path_data, FALSE, TRUE)
##' cyphr::data_admin_init(path_data, path_user = path_alice)
##'
##' # If Bob can also write to the data directory (e.g., it is a
##' # shared git repo, on a shared drive, etc), then he can request
##' # access
##' path_bob <- tempfile()
##' cyphr::ssh_keygen(path_bob, password = FALSE)
##' hash <- cyphr::data_request_access(path_data, path_user = path_bob)
##'
##' # Alice can authorise Bob
##' cyphr::data_admin_authorise(path_data, path_user = path_alice, yes = TRUE)
##'
##' # After which Bob can get the data key
##' cyphr::data_key(path_data, path_user = path_bob)
##'
##' # See the vignette for more details.  This is not the best medium
##' # to explore this.
##'
##' # Cleanup
##' unlink(path_alice, recursive = TRUE)
##' unlink(path_bob, recursive = TRUE)
##' unlink(path_data, recursive = TRUE)
data_request_access <- function(path_data, path_user = NULL, quiet = FALSE) {
  pair <- data_load_keypair_user(path_user)
  data_check_path_data(path_data)

  info <- Sys.info()
  dat <- list(user = info[["user"]],
              host = info[["nodename"]],
              date = Sys.time(),
              pub = pair$pub)
  hash <- openssl_fingerprint(pair$pub)
  hash_str <- bin2str(hash, "")

  if (file.exists(file.path(data_path_cyphr(path_data), hash_str))) {
    message("You appear to already have access")
    return(invisible(hash))
  }

  path_req <- data_path_request(path_data)
  dir.create(path_req, FALSE, TRUE)
  dest <- file.path(path_req, hash_str)
  if (file.exists(dest)) {
    workflow_log(FALSE, "Request is already pending")
  } else {
    workflow_log(quiet, "A request has been added")
    dat$signature <-
      openssl::signature_create(data_key_prep(dat), key = pair$key())
    data_key_save(dat, dest)
  }

  ## The idea here is that they will email or whatever creating a
  ## second line of communication.  Probably this should provide a
  ## hash of the request to the validity of the request can be
  ## checked.  But I'm not really anticipating attacks here.
  ##
  ## Consider taking same approach as whoami, but falling back on
  ## asking instead?
  workflow_log(quiet, "Email someone with access to add you.")
  workflow_log(quiet, paste0("\thash: ", bin2str(hash, ":")))
  if (using_git(path_data)) {
    msg <- c("If you are using git, you will need to commit and push first:",
             "    git add .cyphr",
             '    git commit -m "Please add me to the dataset"',
             '    git push')
    workflow_log(quiet, paste(msg, collapse = "\n"))
  }
  invisible(hash)
}

##' @export
##' @param test Test that the encryption is working?  (Recommended)
##' @rdname data_user
data_key <- function(path_data, path_user = NULL, test = TRUE,
                     quiet = FALSE) {
  x <- data_load_sym(path_data, path_user, quiet)
  if (test) {
    data_test(x, path_data)
  }
  x
}

## Here, key is the data key encrypted with the user's public key.
## Add that to the publicly readable data.
##
## NOTE: Because the logic around overwriting is hard, this will
## overwrite without warning or notice.
data_authorise_write <- function(path_data, sym, dat, yes = FALSE,
                                 quiet = FALSE) {
  workflow_log(quiet, "Adding key %s", data_key_str(dat))
  if (!(yes || prompt_confirm())) {
    msg <- paste("Cancelled adding key ", bin2str((dat$hash)))
    e <- structure(list(message = msg, call = NULL),
                   class = c("cancel_addition", "error", "condition"))
    stop(e)
  }

  ## NOTE: we don't support half-pairs yet so using lower-level
  ## functions.  However, I won't be the only person who wants this.
  ##
  ## We could do:
  ##
  ##   dat$key <- encrypt_data(sym$key(), keypair_openssl(dat$pub, FALSE))
  ##
  ## with the FALSE indicating that we did not want to load the private key.
  ##
  ## but I don't think that the complication here is worthwhile (and
  ## it will work poorly in the case where signed encryption is used).
  dat$key <- openssl::rsa_encrypt(sym$key(), dat$pub)

  hash_str <- bin2str(openssl_fingerprint(dat$pub), "")
  data_key_save(dat, file.path(data_path_cyphr(path_data), hash_str))
  file.remove(dat$filename)

  invisible()
}

data_pub_load <- function(hash, path_request) {
  if (is.raw(hash)) {
    hash_str <- bin2str(hash, "")
  } else {
    hash_str <- gsub(":", "", hash)
    hash <- str2bin(hash_str)
  }
  filename <- file.path(path_request, hash_str)
  if (!file.exists(filename)) {
    stop(sprintf("No key '%s' found at path %s", hash_str, path_request),
         call. = FALSE)
  }
  dat <- readRDS(filename)

  ## Two attempts at verifying the data provided as a key to detect
  ## tampering.
  if (!identical(as.raw(openssl_fingerprint(dat$pub)), as.raw(hash))) {
    stop("Public key hash disagrees for: ", hash_str)
  }

  tryCatch(
    openssl::signature_verify(data_key_prep(dat), dat$signature,
                              pubkey = dat$pub),
    error = function(e) stop("Signature of data does not match for ", hash_str))

  ## Save the filename so we can organise deletion later on
  dat$filename <- filename
  dat
}

data_pubs_load <- function(path) {
  hash <- dir(path, pattern = "^[[:xdigit:]]{32}$")
  dat <- lapply(hash, data_pub_load, path)
  names(dat) <- hash
  class(dat) <- "data_keys"
  dat
}

data_key_str <- function(x, indent = "") {
  hash <- bin2str(openssl_fingerprint(x$pub), ":")
  x$date <- as.character(x$date)
  x <- unlist(x[c("user", "host", "date")])
  sprintf("%s%s\n%s", indent, hash,
          paste(sprintf("%s  %4s: %s",
                        indent, names(x), unlist(x)), collapse = "\n"))
}

##' @export
print.data_keys <- function(x, ...) {
  if (length(x) == 0L) {
    cat("(empty)\n")
  } else {
    cat(sprintf("%d key%s:\n", length(x), ngettext(length(x), "", "s")))
    cat(paste0(vapply(x, data_key_str, character(1), indent = "  "),
               "\n", collapse = ""))
  }
  invisible(x)
}

data_load_sym <- function(path_data, path_user, quiet) {
  data_check_path_data(path_data)
  path_cyphr <- data_path_cyphr(path_data)
  pair <- data_load_keypair_user(path_user)
  hash_str <- bin2str(openssl_fingerprint(pair$pub), "")
  path_data_key <- file.path(path_cyphr, hash_str)
  if (!file.exists(path_data_key)) {
    data_access_error(path_data, path_data_key)
  }
  dat <- readRDS(path_data_key)
  key_sodium(openssl::rsa_decrypt(dat$key, pair$key()))
}

data_access_error <- function(path_data, path_data_key) {
  cmd <- call("data_request_access", path_data)
  cmd <- paste(deparse(cmd, getOption("width", 60L)), collapse = "\n")
  msg <- paste(c("Key file not found; you may not have access",
                 sprintf("(looked in %s)", path_data_key),
                 paste0("To request access, run:\n  ", cmd)),
               collapse = "\n")
  stop(msg, call. = FALSE)
}

data_test <- function(x, path_data) {
  res <- try(decrypt_string(data_path_test(path_data), x), silent = TRUE)
  if (!identical(res, "cyphr")) {
    stop("Decryption failed")
  }
}

workflow_log <- function(quiet, ...) {
  if (!quiet) {
    message(sprintf(...))
  }
}

data_key_prep <- function(x) {
  ## There may be other fields here; in particular "signature" (which
  ## we do not know because it's the hash of the object) and the
  ## private key (but I don't remember which one at this point)
  serialize(unclass(x[c("user", "host", "date", "pub")]), NULL)
}

data_key_save <- function(x, filename) {
  keep <- c("user", "host", "date", "pub", "signature", "key")
  saveRDS(x[names(x) %in% keep], filename)
}

########################

## Do we want some sort of general cache of these things?  It might be
## nice but I do not know how to do it (especially if it is to be a
## timed cache)
data_load_keypair_user <- function(path_user) {
  if (inherits(path_user, "cyphr_keypair")) {
    pair <- path_user
    if (pair$type != "openssl") {
      stop(sprintf("Expected an 'openssl' keypair (but recieved %s)",
                   pair$type))
    }
  } else if (is.character(path_user) || is.null(path_user)) {
    pair <- keypair_openssl(path_user, path_user)
  } else {
    stop("Invalid input for 'path_user'")
  }
  pair
}

## The root path that all our stuff gets put into
data_path_cyphr <- function(path) {
  file.path(path, ".cyphr")
}

## A test file that we can use to make sure everything works
data_path_test <- function(path_data) {
  file.path(data_path_cyphr(path_data), "test")
}

## A directory for data access requests
data_path_request <- function(path_data) {
  file.path(data_path_cyphr(path_data), "requests")
}

data_check_path_data <- function(path_data, fail = TRUE) {
  ok <- file.exists(data_path_test(path_data))
  if (fail && !ok) {
    stop("cyphr not set up for ", path_data)
  }
  invisible(ok)
}

data_load_request <- function(path_data, hash = NULL, quiet = FALSE) {
  path_req <- data_path_request(path_data)
  if (is.null(hash)) {
    keys <- data_admin_list_requests(path_data)
    nk <- length(keys)
    workflow_log(
      quiet,
      ngettext(nk, "There is 1 request for access",
               sprintf("There are %d requests for access", nk)))
  } else {
    if (is.character(hash)) {
      keys <- lapply(hash, data_pub_load, path_req)
    } else if (is.raw(hash)) {
      keys <- list(data_pub_load(hash, path_req))
    } else {
      stop("Invalid type for 'hash'")
    }
    names(keys) <- vapply(keys, function(x)
      bin2str(openssl_fingerprint(x$pub), ""), character(1))
    class(keys) <- "data_keys"
  }
  keys
}
