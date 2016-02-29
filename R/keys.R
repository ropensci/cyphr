## This needs to support the three different interfaces in sodium:
##   data_encrypt(data, key, nonce)
##   simple_encrypt(data, pub)
##   auth_encrypt(data, key, pub)
## So probably what we want to pass around is a little object with
## instructions on how to encrypt/decrpt with the method and the keys
## explictly given.

##' Load sodium keys for use with \code{encrypt}/\code{decrypt}.
##'
##' Note that the interface here is quite different to that for
##' \code{\link{config_openssl}} which loads ssh keys; here we expect
##' keys to be provided as raw data, or as links to binary files that
##' contain that raw data.  In contrast for openssl we use standard
##' key formats.
##' @title  Encryption configuration
##'
##' @param path_key Path to, or contents of, the symmetric key
##'   (\code{config_sodium_symmetric}) or your personal private key
##'   (\code{config_sodium_public},
##'   \code{config_sodium_authenticated}).  For
##'   \code{config_sodium_public}, this may be \code{NULL} in which
##'   case only encryption can be carried out.
##'
##' @param path_pub Path to, or contents of, the public key; your
##'   personal public key (\code{config_sodium_public}) or the other
##'   party's key (\code{config_sodium_authenticated}).
##'
##' @rdname encryptr_config
##' @export
config_sodium_symmetric <- function(path_key) {
  key <- load_key_sodium_private(path_key)
  config("sodium_symmetric",
         function(msg, ...) sodium::data_encrypt(msg, key, ...),
         function(msg, ...) sodium::data_decrypt(msg, key, ...))
}

##' @export
##' @rdname encryptr_config
config_sodium_public <- function(path_pub, path_key) {
  pub <- load_key_sodium_public(path_pub)
  if (is.null(path_key)) {
    decrypt <- cant_decrypt
  } else {
    key <- load_key_sodium_private(path_key)
    decrypt <- function(msg, ...) sodium::simple_decrypt(msg, key)
  }
  config("sodium_public",
         function(msg, ...) sodium::simple_encrypt(msg, pub),
         decrypt)
}

##' @export
##' @rdname encryptr_config
config_sodium_authenticated <- function(path_pub, path_key) {
  pub <- load_key_sodium_public(path_pub)
  key <- load_key_sodium_private(path_key)
  if (is.null(key)) {
    stop("Private key is required for authenticated encryption")
  }
  config("sodium_authenticated",
         function(msg, ...) sodium::auth_encrypt(msg, key, pub, ...),
         function(msg, ...) sodium::auth_decrypt(msg, key, pub, ...))
}

##' Load keys for use with \code{\link{encrypt}} /
##' \code{\link{decrypt}}, using openssl encryption.  This is in
##' contrast to the sodium supported keys in (e.g.,
##' \code{\link{config_sodium_symmetric}} as here we assume that keys
##' are specified as the path to files as there are standard formats
##' for these.
##' @title Load openssl keys
##' @param path The path to the key.  If \code{NULL}, the environment
##'   variables \code{USER_KEY} and \code{USER_PUBKEY} are checked,
##'   and if they are empty then \code{~/.ssh/id_rsa} is used.  The
##'   path can be either the full path to a public or private key, or
##'   it can be the path to a directory containing the keypair (as
##'   \code{id_rsa} and \code{id_rsa.pub}).
##' @param private A logical scalar indicating if the private key
##'   should be loaded.  Because keypairs are often password
##'   protected, and because public keys are useful on their own,
##'   often it will not be needed to unlock and load the private key.
##' @param envelope A logical scalar indicating if the "envelope"
##'   functions should be used.  If \code{TRUE}, then this is used for
##'   messaging (via \code{\link{encrypt_envelope}}).  This is what
##'   you would use to communicate with a third party using shared
##'   public keys and non-shared private keys.  If \code{FALSE}, then
##'   \code{\link{rsa_encrypt}} is used.  This is less useful because
##'   it can only encrypt messages smaller than the size of the key.
##' @export
##' @examples
##' \dontrun{
##' cfg <- config_openssl(private=FALSE)
##' secret <- encrypt_string("hello", NULL, cfg)
##' decrypt_string(secret, cfg)
##' }
config_openssl <- function(path=NULL, private=TRUE, envelope=TRUE) {
  openssl__decrypt_envelope <- function(x, key) {
    openssl::decrypt_envelope(x$data, x$iv, x$session, key)
  }
  dat <- load_key_openssl(path, private)
  pub <- dat$pub
  key <- dat$key
  if (envelope) {
    encrypt <- function(msg, ...) openssl::encrypt_envelope(msg, pub)
    decrypt <- function(msg, ...) openssl__decrypt_envelope(msg, key)
  } else {
    encrypt <- function(msg, ...) openssl::rsa_encrypt(msg, pub)
    decrypt <- function(msg, ...) openssl::rsa_decrypt(msg, key)
  }
  if (is.null(key)) {
    decrypt <- cant_decrypt
  }
  config("openssl", encrypt, decrypt)
}

config <- function(type, encrypt, decrypt) {
  structure(list(type=type, encrypt=encrypt, decrypt=decrypt),
            class="encryptr_config")
}

##' @export
print.encryptr_config <- function(x, ...) {
  cat(sprintf("<encryptr: %s>\n", x$type))
}

##' @export
print.key_pair <- function(x, ...) {
  cat(sprintf("<%s key pair>\n", class(x)[[1L]]))
  invisible(x)
}

make_config <- function(x, ...) {
  UseMethod("make_config")
}

make_config.encryptr_config <- function(x, ...) {
  x
}

make_config.rsa_pair <- function(x, envelope=TRUE, ...) {
  config_openssl(x$pub, x$key, envelope)
}

## Need to switch between "authenticated"
make_config.sodium_pair <- function(x, simple=TRUE, ...) {
  if (simple) {
    config_sodium_public(x$pub, x$key)
  } else {
    config_sodium_authenticated(x$pub, x$key)
  }
}

make_config.sodium_symmetric <- function(x, ...) {
  config("symmetric",
         function(msg, ...) sodium::data_encrypt(msg, x, ...),
         function(msg, ...) sodium::data_decrypt(msg, x, ...))
}

cant_decrypt <- function(msg, ...) {
  stop("decryption not supported")
}
