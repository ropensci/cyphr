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
##'   (\code{config_symmetric}) or your personal private key
##'   (\code{config_public}, \code{config_authenticated}).  For
##'   \code{config_public}, this may be \code{NULL} in which case only
##'   encryption can be carried out.
##'
##' @param path_pub Path to, or contents of, the public key; your
##'   personal public key (\code{config_public}) or the other party's
##'   key (\code{config_authenticated}).
##'
##' @rdname encryptr_config
##' @export
config_symmetric <- function(path_key) {
  key <- config_get_key(path_key)
  config("symmetric",
         function(msg, ...) sodium::data_encrypt(msg, key, ...),
         function(msg, ...) sodium::data_decrypt(msg, key, ...))
}

##' @export
##' @rdname encryptr_config
config_public <- function(path_pub, path_key) {
  pub <- config_get_key(path_pub)
  if (is.null(path_key)) {
    decypt <- function(msg, ...) stop("decryption not supported")
  } else {
    key <- config_get_key(path_key)
    decrypt <- function(msg, ...) sodium::simple_decrypt(msg, key)
  }
  config("public",
         function(msg, ...) sodium::simple_encrypt(msg, pub),
         decrypt)
}

##' @export
##' @rdname encryptr_config
config_authenticated <- function(path_pub, path_key) {
  pub <- config_get_key(path_pub)
  key <- config_get_key(path_key)
  config("authenticated",
         function(msg, ...) sodium::auth_encrypt(msg, key, pub, ...),
         function(msg, ...) sodium::auth_decrypt(msg, key, pub, ...))
}

##' @export
print.encryptr_config <- function(x, ...) {
  cat(sprintf("<encryptr: %s>\n", x$type))
}

config <- function(type, encrypt, decrypt) {
  structure(list(type=type, encrypt=encrypt, decrypt=decrypt),
            class="encryptr_config")
}

config_get_key <- function(x) {
  if (is.raw(x)) {
    x
  } else {
    read_binary(x)
  }
}

## TODO: which functions here are the API bits?
##
##  Functions for loading keys seems sensible, but I'm not sure what
##  the best thing to do here is.


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
  force(x)
  if (envelope) {
    encrypt <- function(msg, ...) openssl::encrypt_envelope(msg, x$pub)
    decrypt <- function(msg, ...) openssl__decrypt_envelope(msg, x$key)
  } else {
    encrypt <- function(msg, ...) openssl::rsa_encrypt(msg, x$pub)
    decrypt <- function(msg, ...) openssl::rsa_decrypt(msg, x$key)
  }
  if (is.null(x$key)) {
    decrypt <- cant_decrypt
  }
  config("openssl", encrypt, decrypt)
}

## Need to switch between "authenticated"
make_config.sodium_pair <- function(x, simple=TRUE, ...) {
  if (simple) {
    encrypt <- function(msg, ...) sodium::simple_encrypt(msg, x$pub)
    if (is.null(x$key)) {
      decrypt <- cant_decrypt
    } else {
      decrypt <- function(msg, ...) sodium::simple_decrypt(msg, x$key)
    }
    type <- "sodium_simple"
  } else {
    if (is.null(x$key)) {
      stop("Private key is required for authenticated encryption")
    }
    encrypt <- function(msg, ...) sodium::auth_encrypt(msg, x$pub, x$key)
    decrypt <- function(msg, ...) sodium::auth_decrypt(msg, x$pub, x$key)
    type <- "sodium_authenticated"
  }
  config(type, encrypt, decrypt)
}

make_config.sodium_symmetric <- function(x, ...) {
  config("symmetric",
         function(msg, ...) sodium::data_encrypt(msg, x, ...),
         function(msg, ...) sodium::data_decrypt(msg, x, ...))
}

cant_decrypt <- function(msg, ...) {
  stop("decryption not supported")
}
