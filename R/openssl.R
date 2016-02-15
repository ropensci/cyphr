config_openssl <- function(path, private=TRUE) {
  dat <- load_key_ssl(path, private)
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

## Valid values for private are TRUE/FALSE only
find_key_ssl <- function(path=NULL, private=TRUE) {
  if (is.list(path)) {
    if (private && is.null(path$key)) {
      stop("This is a bug in the package")
    }
    return(path)
  }
  if (is.null(path)) {
    ## Places to look:
    path <- Sys_getenv(c("USER_KEY", "USER_PUBKEY"))
    if (is.null(path) && file.exists("~/.ssh/id_rsa")) {
      path <- "~/.ssh/id_rsa"
    } else {
      stop("Could not determine location of public key")
    }
  }
  if (!is.character(path) || length(path) != 1L) {
    stop("Invalid type for key")
  }
  if (!file.exists(path)) {
    stop("Key does not exist at ", path)
  }

  if (is_directory(path)) {
    dir <- path
    ## TODO: Consider running through a series of possible keys here.
    ## We might also support dsa or ecdsa keys.  In practice rsa
    ## should work enough of the time.
    pub <- file.path(path, "id_rsa.pub")
    key <- file.path(path, "id_rsa")
  } else {
    if (grepl("\\.pub$", path)) {
      pub <- path
      key <- sub("\\.pub$", "", pub)
      dir <- dirname(path)
    } else {
      key <- path
      pub <- paste0(key, ".pub")
      dir <- dirname(path)
    }
  }

  if (!file.exists(pub)) {
    stop("Public key not found at ", pub)
  }
  if (!file.exists(key)) {
    if (private) {
      stop("Private key not found at ", key)
    } else {
      key <- NULL
    }
  }

  list(dir=normalizePath(dir),
       pub=normalizePath(pub),
       key=if (is.null(key)) NULL else normalizePath(key))
}

load_key_ssl <- function(path, private=TRUE) {
  if (inherits(path, "key_pair")) {
    ret <- path
  } else if (inherits(path, "pubkey")) {
    if (isTRUE(private)) {
      stop("Cannot load private key")
    } else if (identical(private, FALSE)) {
      private <- NULL
    } else if (!inherits(private, "key")) {
      stop("Invalid input for private")
    }
    ret <- list(path=NULL,
                pub=path,
                key=private)
    class(ret) <- c("rsa_pair", "key_pair")
  } else {
    dat <- find_key_ssl(path, private)
    ret <- list(path=dat,
                pub=openssl::read_pubkey(dat$pub),
                key=if (private) openssl::read_key(dat$key) else NULL)
    class(ret) <- c("rsa_pair", "key_pair")
  }
  ret
}

key_hash <- function(k) {
  openssl:::fingerprint(k)
}
