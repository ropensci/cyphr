##' Wrapper around \code{ssh-keygen}(1).  In general this should not
##' be used (generate keys yourself with \code{ssh-keygen} at the
##' command line.  However this is useful for testing and
##' demonstration so I have included it to make that easier.  Once a
##' key has been generated it can be used with
##' \code{\link{config_openssl}}.
##'
##' @title Wrapper around ssh-keygen
##' @param path A directory in which to create a keypair.  If the path
##'   does not exist it will be created.
##' @param password The password for the key.  The default will prompt
##'   interactively (but without echoing the password).  Other valid
##'   options are \code{FALSE} (no password) or a string.
##' @return The \code{path}, invisibly.  This is useful in the case
##'   where \code{path} is \code{\link{tempfile()}}.
##' @export
##' @examples
##' \dontrun{
##' # Generate a new key in a temporary directory:
##' path <- ssh_keygen(password=FALSE)
##' dir(path) # will contain id_rsa and id_rsa.pub
##'
##' # This key can now be used via config_openssl:
##' cfg <- config_openssl(path)
##' secret <- encrypt_string("hello", NULL, cfg)
##' decrypt_string(secret, cfg)
##' }
ssh_keygen <- function(path=tempfile(), password=TRUE) {
  ## TODO: Talk with Jeroen about whether this is needed; can the
  ## openssl package write out keys that work like plain ssh keys?
  dest <- file.path(path, "id_rsa")
  if (file.exists(path) && !is_directory(path)) {
    stop("path exists but is not a directory")
  }
  if (file.exists(dest)) {
    stop(dest, " exists already -- not overwriting")
  }
  ssh_keygen <- Sys.which("ssh-keygen")
  if (ssh_keygen == "") {
    stop("Can not find ssh-keygen")
  }
  dir.create(path, FALSE, TRUE)

  if (isTRUE(password)) {
    pw <- get_password_str(TRUE, "Enter passphrase: ")
  } else if (identical(password, FALSE)) {
    pw <- "''"
  } else if (is.character(password)) {
    pw <- if (nzchar(password)) password else "''"
  } else {
    stop("Invalid input for password")
  }

  code <- system2(ssh_keygen, c("-q", "-N", pw, "-f", dest))
  if (code != 0L) {
    stop("Error running ssh-keygen")
  }

  invisible(path)
}

## This is close, but not quite there yet.
##
## Change this to be:
##
##   public=NULL, private=NULL
##
## The NULL path will go through the search through
##
##   (USER_KEY / USER_PUBKEY), ~/.ssh
##
## if a directory, then search for the appropriate file within it
## (id_rsa or id_rsa.pub).
##
## If either is FALSE we do not search for the key and return a NULL
## key instead.
##
## This approach is better because we never really want to load both
## parts of a keypair.  But OTOH it will be useful for demo cases.
find_key_openssl <- function(public=NULL, private=TRUE) {
  pub <- find_key_openssl1(public, TRUE)
  if (isFALSE(private)) {
    key <- NULL
  } else {
    ## This does not deal with the case of non-id_rsa keypairs
    if (isTRUE(private) || is.null(private)) {
      private <- dirname(pub)
    }
    key <- find_key_openssl1(private, FALSE)
  }
  list(pub=pub, key=key)
}

find_key_openssl1 <- function(path, public) {
  if (inherits(path, "rsa")) {
    return(path)
  }
  nm <- if (public) "public" else "private"
  if (is.null(path)) {
    path <- Sys_getenv(if (public) "USER_PUBKEY" else "USER_KEY")
    if (is.null(path) && file.exists("~/.ssh/id_rsa")) {
      path <- if (public) "~/.ssh/id_rsa.pub" else "~/.ssh/id_rsa"
    } else if (!is.character(path) && file.exists(path)) {
      stop("Could not determine location of public key")
    }
  } else if (!is.character(path) || length(path) != 1L) {
    stop("Invalid type for key")
  }
  if (!file.exists(path)) {
    stop("Key does not exist at ", path)
  }
  if (is_directory(path)) {
    path <- file.path(path, if (public) "id_rsa.pub" else "id_rsa")
  }
  if (!file.exists(path)) {
    stop(sprintf("%s key not found at %s", nm, path))
  }
  if (is.null(path)) path else normalizePath(path)
}

load_key_openssl <- function(public, private=TRUE) {
  if (inherits(public, "rsa_pair")) {
    ret <- public
  } else {
    ret <- find_key_openssl(public, private)
    if (!is_rsa(ret$pub)) {
      ret$pub <- openssl::read_pubkey(ret$pub)
    }
    if (!is_rsa(ret$key) && !is.null(ret$key)) {
      pw <- function(...) {
        msg <- sprintf("Please enter password for private key %s: ", ret$key)
        get_password_str(FALSE, msg)
      }
      ret$key <- openssl::read_key(ret$key, pw)
    }
    class(ret) <- c("rsa_pair", "key_pair")
  }
  ret
}

openssl_fingerprint <- function(k) {
  as.list(k)$fingerprint
}

is_rsa <- function(x, public=NULL) {
  if (is.null(public)) {
    inherits(x, "rsa")
  } else if (public) {
    inherits(x, "rsa") && inherits(x, "pubkey")
  } else {
    inherits(x, "rsa") && inherits(x, "key")
  }
}
