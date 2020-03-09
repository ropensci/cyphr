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
##'   things in a hidden directory within this path.  By default in
##'   most functions we will search down the tree until we find the
##'   .cyphr directory
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
  if (!is_directory(path_data)) {
    stop("'path_data' must exist and be a directory")
  }

  pair <- data_load_keypair_user(path_user)
  found <- data_check_path_data(path_data, search = TRUE, fail = FALSE)

  if (is.null(found)) {
    workflow_log(quiet, "Generating data key")
    path_data <- I(path_data) # prevent recursion
    path_cyphr <- data_path_cyphr(path_data)
    dir.create(path_cyphr, FALSE, TRUE)
    on.exit(unlink(path_cyphr, recursive = TRUE), add = TRUE)
    data_version_write(path_data)
    version <- data_version_read(path_data)

    dir.create(data_path_request(path_data), FALSE, TRUE)
    dir.create(data_path_user_key(path_data, NULL, version), FALSE, TRUE)

    ## Now, the idea is to create a key for the data set:
    sym <- key_sodium(sodium::keygen())

    ## NOTE: If anything below fails, this file needs deleting, as
    ## this is the file that we check to see if things are set up
    ## correctly (data_check_path_data()).
    path_test <- data_path_test(path_data)
    encrypt_string("cyphr", sym, path_test)
    on.exit({
      workflow_log(quiet, "Removing data key")
      suppressWarnings(file.remove(path_test))
    }, add = TRUE)

    ## Just check that this all works:
    decrypt_string(path_test, sym)

    workflow_log(quiet, "Authorising ourselves")

    ## Now, make a copy of the public key; probably what needs to
    ## happen here is that we authorise ourselves but this case is a
    ## little different because we already have the symmetric key.
    ## But this bit is shared; we need to copy the files around a
    ## bunch.
    hash <- data_request_access(path_data, pair, quiet = TRUE)
    path_req <- data_path_request(path_data)
    ## NOTE: here we can't use data_admin_authorise because we can't
    ## load the symmetric key from the files we're trying to write!
    dat <- data_pub_load(hash, path_req, version)
    data_authorise_write(path_data, sym, dat, TRUE, quiet)

    dir.create(data_path_template(path_data), FALSE, TRUE)
    file_copy(cyphr_file("template/README.md"),
              file.path(data_path_cyphr(path_data), "README.md"))
    file_copy(cyphr_file("template/template_request"),
              file.path(data_path_template(path_data), "request"))
    file_copy(cyphr_file("template/template_authorise"),
              file.path(data_path_template(path_data), "authorise"))
  } else {
    path_data <- found
    workflow_log(quiet, paste("Already set up at", path_data))
  }

  workflow_log(quiet, "Verifying")
  x <- data_key(path_data, pair, test = TRUE, cache = FALSE)
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
data_admin_authorise <- function(path_data = NULL, hash = NULL,
                                 path_user = NULL, yes = FALSE,
                                 quiet = FALSE) {
  path_data <- data_check_path_data(path_data, search = TRUE)
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
    workflow_log(quiet, sprintf("Added %d key%s", nok, ngettext(nok, "", "s")))
    p <- file.path(data_path_template(path_data), "authorise")
    if (file.exists(p)) {
      users <- paste(vapply(keys, function(x) x$user, character(1)),
                     collapse = ", ")
      msg <- gsub("$USERS", users, readLines(p), fixed = TRUE)
      workflow_log(quiet, msg)
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
data_admin_list_requests <- function(path_data = NULL) {
  data_pubs_load(path_data, TRUE)
}

##' @export
##' @rdname data_admin
data_admin_list_keys <- function(path_data = NULL) {
  data_pubs_load(path_data, FALSE)
}

##' User commands
##' @title User commands
##'
##' @param path_data Path to the data.  If not given, then we look
##'   recursively down below the working directory for a ".cyphr"
##'   directory, and use that as the data directory.
##'
##' @param path_user Path to the directory with your user key.
##'   Usually this can be omitted.  This argument is passed in as both
##'   \code{pub} and \code{key} to \code{\link{keypair_openssl}}.
##'   Briefly, if this argument is not given we look at the
##'   environment variables \code{USER_PUBKEY} and \code{USER_KEY} -
##'   if set then these must refer to path of your public and private
##'   keys.  If these environment variables are not set then we fall
##'   back on \code{~/.ssh/id_rsa.pub} and \code{~/.ssh/id_rsa},
##'   which should work in most environments.  Alternatively, provide
##'   a path to a directory where the file \code{id_rsa.pub} and
##'   \code{id_rsa} can be found.
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
data_request_access <- function(path_data = NULL, path_user = NULL,
                                quiet = FALSE) {
  path_data <- data_check_path_data(path_data, search = TRUE)
  version <- data_version_read(path_data)
  pair <- data_load_keypair_user(path_user)

  info <- Sys.info()
  dat <- list(user = info[["user"]],
              host = info[["nodename"]],
              date = Sys.time(),
              pub = pair$pub)
  hash <- data_key_fingerprint(pair$pub, version)

  if (file.exists(data_path_user_key(path_data, hash, version))) {
    message("You appear to already have access")
    return(invisible(hash))
  }

  path_req <- data_path_request(path_data)
  dir.create(path_req, FALSE, TRUE)
  dest <- file.path(path_req, bin2str(hash, ""))
  if (file.exists(dest)) {
    workflow_log(FALSE, "Request is already pending")
  } else {
    workflow_log(quiet, "A request has been added")
    data_key_save(dat, dest)
  }

  hash_str <- bin2str(hash, ":")
  p <- file.path(data_path_template(path_data), "request")
  if (file.exists(p)) {
    msg <- gsub("$HASH", hash_str, readLines(p), fixed = TRUE)
    workflow_log(quiet, msg)
  }

  invisible(hash)
}

##' @export
##'
##' @param test Test that the encryption is working?  (Recommended)
##'
##' @param cache Cache the key within the session.  This will be
##'   useful if you are using ssh keys that have passwords, as if the
##'   key is found within the cache, then you will not have to
##'   re-enter your password.  Using \code{cache = FALSE} neither
##'   looks for the key in the cache, nor saves it.
##'
##' @rdname data_user
data_key <- function(path_data = NULL, path_user = NULL, test = TRUE,
                     quiet = FALSE, cache = TRUE) {
  path_data <- data_check_path_data(path_data, search = TRUE)
  if (cache && path_data %in% names(data_cache$keys)) {
    return(data_cache$keys[[path_data]])
  }
  x <- data_load_sym(path_data, path_user, quiet)
  if (test) {
    data_test(x, path_data)
  }
  if (cache) {
    data_cache$keys[[path_data]] <- x
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
  version <- data_version_read(path_data)
  workflow_log(quiet, sprintf("Adding key %s", data_key_str(dat, version)))
  if (!(yes || prompt_confirm())) {
    msg <- paste("Cancelled adding key ", bin2str((dat$hash)))
    e <- structure(list(message = msg, call = NULL),
                   class = c("cancel_addition", "error", "condition"))
    stop(e)
  }

  dat$key <- openssl::rsa_encrypt(sym$key(), dat$pub)

  hash <- data_key_fingerprint(dat$pub, version)
  dest <- data_path_user_key(path_data, hash, version)
  data_key_save(dat, dest)
  file.remove(dat$filename)

  invisible()
}

data_pub_load <- function(hash, path, version) {
  if (is.raw(hash)) {
    hash_str <- bin2str(hash, "")
  } else {
    hash_str <- gsub(":", "", hash)
    hash <- str2bin(hash_str)
  }

  filename <- file.path(path, hash_str)
  if (!file.exists(filename)) {
    stop(sprintf("No key '%s' found at path %s", hash_str, path),
         call. = FALSE)
  }
  dat <- readRDS(filename)
  expected <- data_key_fingerprint(dat$pub, version)

  if (!identical(as.raw(expected), as.raw(hash))) {
    stop("Public key hash disagrees for: ", hash_str)
  }

  ## Save the filename so we can organise deletion later on
  dat$filename <- filename
  dat
}

data_pubs_load <- function(path_data, requests) {
  path_data <- data_check_path_data(path_data, search = TRUE)
  version <- data_version_read(path_data)
  if (requests) {
    path <- data_path_request(path_data)
  } else {
    path <- data_path_user_key(path_data, NULL, version)
  }
  hash <- dir(path, pattern = "^[[:xdigit:]]{32,}$")
  dat <- lapply(hash, data_pub_load, path, version)
  names(dat) <- hash
  class(dat) <- "data_keys"
  attr(dat, "version") <- version
  dat
}

data_key_str <- function(x, version, indent = "") {
  hash <- bin2str(data_key_fingerprint(x$pub, version), ":")
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
    version <- attr(x, "version", exact = TRUE)
    cat(sprintf("%d key%s:\n", length(x), ngettext(length(x), "", "s")))
    cat(paste0(vapply(x, data_key_str, character(1), version, indent = "  "),
               "\n", collapse = ""))
  }
  invisible(x)
}

data_load_sym <- function(path_data, path_user, quiet) {
  path_data <- data_check_path_data(path_data)
  path_cyphr <- data_path_cyphr(path_data)
  pair <- data_load_keypair_user(path_user)
  version <- data_version_read(path_data)

  hash <- data_key_fingerprint(pair$pub, version)
  path_data_key <- data_path_user_key(path_data, hash, version)
  if (!file.exists(path_data_key)) {
    data_access_error(path_data, path_data_key)
  }

  dat <- readRDS(path_data_key)
  key_sodium(openssl::rsa_decrypt(dat$key, pair$key()))
}

data_access_error <- function(path_data, path_data_key) {
  cmd <- call("data_request_access", as.character(path_data))
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

workflow_log <- function(quiet, msg) {
  if (!quiet) {
    message(paste(msg, collapse = "\n"))
  }
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

data_path_template <- function(path_data) {
  file.path(data_path_cyphr(path_data), "template")
}

## A directory for data access requests
data_path_request <- function(path_data) {
  file.path(data_path_cyphr(path_data), "requests")
}

data_path_user_key <- function(path_data, hash, version) {
  path <- data_path_cyphr(path_data)
  if (version >= numeric_version("1.1.0")) {
    path <- file.path(path, "keys")
  }
  if (is.null(hash)) {
    path
  } else {
    file.path(path, bin2str(hash, ""))
  }
}

data_path_version <- function(path_data) {
  file.path(data_path_cyphr(path_data), "version")
}

data_version_write <- function(path_data) {
  dest <- data_path_version(path_data)
  dir.create(dirname(dest), FALSE, TRUE)
  writeLines(as.character(data_schema_version()),
             data_path_version(path_data))
}

data_version_read <- function(path_data) {
  path_data <- normalizePath(path_data, mustWork = TRUE)
  if (!exists(path_data, data_cache$versions)) {
    p <- data_path_version(path_data)
    if (file.exists(p)) {
      v <- numeric_version(readLines(p))
    } else {
      v <- numeric_version("1.0.0")
    }
    cur <- data_schema_version()
    if (v < cur) {
      msg <- c(
        sprintf(
          "Your cyphr schema version is out of date (found %s, current is %s)",
          v, cur),
        sprintf(
          'Please run cyphr:::data_schema_migrate("%s")',
          path_data))
      warning(paste(msg, collapse = "\n"), immediate. = TRUE, call. = FALSE)
    }
    if (v > cur) {
      msg <- sprintf(
        "Upgrade to cyphr version %s (or newer) to use use this directory",
        v)
      stop(msg, call. = FALSE)
    }
    data_cache$versions[[path_data]] <- v
  }
  data_cache$versions[[path_data]]
}

data_check_path_data <- function(path_data, fail = TRUE, search = FALSE) {
  if (search && !inherits(path_data, "AsIs")) {
    path_data <-
      find_file_descend(".cyphr", path_data %||% getwd()) %||%
      path_data %||%
      getwd()
  }
  success <- file.exists(data_path_test(path_data))
  if (!success && fail) {
    stop("cyphr not set up for ", path_data)
  }
  if (success) I(path_data) else NULL
}

data_load_request <- function(path_data, hash = NULL, quiet = FALSE) {
  path_req <- data_path_request(path_data)
  version <- data_version_read(path_data)
  if (is.null(hash)) {
    keys <- data_admin_list_requests(I(path_data))
    n <- length(keys)
    what <- ngettext(n, "request", "requests")
    workflow_log(quiet, sprintf("There is %d %s for access", n, what))
  } else {
    if (is.character(hash)) {
      keys <- lapply(hash, data_pub_load, path_req, version)
    } else if (is.raw(hash)) {
      keys <- list(data_pub_load(hash, path_req, version))
    } else {
      stop("Invalid type for 'hash'")
    }
    names(keys) <- vapply(keys, function(x)
      bin2str(data_key_fingerprint(x$pub, version), ""), character(1))
    class(keys) <- "data_keys"
    attr(keys, "version") <- version
  }
  keys
}


data_key_fingerprint <- function(k, version) {
  if (version >= numeric_version("1.1.0")) {
    hashfun <- openssl::sha256
  } else {
    hashfun <- openssl::md5
  }
  openssl::fingerprint(k, hashfun)
}


data_cache <- new.env(parent = emptyenv())
data_pkg_init <- function() {
  rm(list = ls(data_cache, all.names = TRUE), envir = data_cache)
  data_cache$schema_version <- numeric_version("1.1.0")
  data_cache$versions <- list()
  data_cache$keys <- list()
}


data_schema_version <- function() {
  data_cache$schema_version
}


data_schema_migrate <- function(path_data) {
  path_data <- data_check_path_data(path_data, search = TRUE)
  version <- data_version_read(path_data)
  cur <- data_schema_version()
  if (cur == version) {
    message("Everything up to date!")
    return(invisible())
  }

  ## If we change the format again, we'll need to deal with this, but
  ## hopefully we won't!
  stopifnot(cur == numeric_version("1.1.0"),
            version == numeric_version("1.0.0"))

  path_keys <- data_path_user_key(path_data, NULL, cur)
  dir.create(path_keys, FALSE, TRUE)

  path_cyphr <- data_path_cyphr(path_data)

  keys <- dir(path_cyphr, "^[[:xdigit:]]{32}$")

  keys <- data_admin_list_keys(path_data)
  requests <- data_admin_list_requests(path_data)

  dir.create(data_path_user_key(path_data, NULL, cur), FALSE, TRUE)

  for (k in keys) {
    hash_old <- data_key_fingerprint(k$pub, version)
    hash_new <- data_key_fingerprint(k$pub, cur)
    message(sprintf("Migrating key %s/%s (%s)",
                    k$user, k$host, bin2str(hash_old, "")))
    file.rename(data_path_user_key(path_data, hash_old, version),
                data_path_user_key(path_data, hash_new, cur))
  }

  path_req <- data_path_request(path_data)
  for (k in requests) {
    hash_old <- data_key_fingerprint(k$pub, version)
    hash_new <- data_key_fingerprint(k$pub, cur)
    message(sprintf("Migrating request %s/%s (%s)",
                    k$user, k$host, bin2str(hash_old, "")))
    file.rename(file.path(path_req, hash_old),
                file.path(path_req, hash_new))
  }

  data_cache$versions[[path_data]] <- NULL
  data_version_write(path_data)
  invisible()
}
