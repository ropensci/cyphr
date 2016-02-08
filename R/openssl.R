## TODO: There's a ton of duplication here with key.R: load_key_rsa;
## combine the two sets of functions.
openssl_read <- function(path, both=TRUE) {
  if (is.null(path)) {
    path <- Sys.getenv("USER_KEY", "~/.ssh/id_rsa")
  } else if (is_directory(path)) {
    path <- file.path(path, "id_rsa")
    if (!file.exists(path)) {
      stop("Did not find id_rsa file at path ", path)
    }
  } else if (file.exists(path)) {
    path <- sub("([^/]+)\\.pub$", "\\1", path)
  } else {
    stop("path does not exist: ", path)
  }
  if (both) {
    key <- openssl::read_key(path, openssl_password(path))
  } else {
    key <- NULL
  }
  pub <- openssl::read_pubkey(paste0(path, ".pub"))
  list(key=key, pub=pub, path=path)
}

config_openssl <- function(path) {
  dat <- openssl_read(path)
  key <- dat$key
  pub <- dat$pub
  config(
    "openssl",
    function(msg, ...) openssl::encrypt_envelope(msg, pub),
    function(msg, ...) openssl__decrypt_envelope(msg, key))
}

openssl__decrypt_envelope <- function(x, key) {
  openssl::decrypt_envelope(x$data, x$iv, x$session, key)
}

openssl_password <- function(path_key) {
  msg <- sprintf("Please enter password for private key %s", path_key)
  function(.) {
    get_password_str(FALSE, 0, msg)
  }
}

as_character <- function(x) {
  capture.output(print(x))
}

##' Wrapper around ssh-keygen(1).
##'
##' @title Wrapper around ssh-keygen
##' @param path A directory in which to create a keypair
##' @param password The password for the key.  The default will prompt
##'   interactively (but without echoing the password).  Other valid
##'   options are \code{FALSE} (no password), a string or a function
##'   that will take a single argument "prompt" and return a string
##'   password (as with the openssl package).
##' @export
ssh_keygen <- function(path=tempfile(), password=TRUE) {
  ## TODO: Talk with Jeroen about whether this is needed; can the
  ## openssl package write out keys that work like plain ssh keys?
  dest <- file.path(path, "id_rsa")
  if (file.exists(path) && !is_directory(path)) {
    stop("path exists but is not a directory")
  }
  if (file.exists(path)) {
    stop(dest, " exists already -- not overwriting")
  }
  ssh_keygen <- Sys.which("ssh-keygen")
  if (ssh_keygen == "") {
    stop("Can not find ssh-keygen")
  }
  dir.create(path, FALSE, TRUE)

  if (isTRUE(password)) {
    pw <- get_password_str(TRUE)
  } else if (identical(password, FALSE)) {
    pw <- "''"
  } else if (is.character(password)) {
    pw <- if (nzchar(password)) password else "''"
  } else if (is.function(password)) {
    pw <- password("Enter password: ") # as in openssl
  } else {
    stop("Invalid input for password")
  }

  code <- system2(ssh_keygen, c("-q", "-N", pw, "-f", dest))
  if (code != 0L) {
    stop("Error running ssh-keygen")
  }

  invisible(path)
}
