## This needs to support the three different interfaces in sodium:
##   data_encrypt(data, key, nonce)
##   simple_encrypt(data, pub)
##   auth_encrypt(data, key, pub)
## So probably what we want to pass around is a little object with
## instructions on how to encrypt/decrpt with the method and the keys
## explictly given.

##' Load keys for use with \code{encrypt}/\code{decrypt}
##'
##' This interface will change because I'd like to push it into global
##' state with \emph{named} things that get pulled from a global cache
##' of options so that the wrappers can be as thin as possible.  But
##' for now, these are the full things and will probably always be
##' supported.
##'
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
config_public <- function(path_key, path_pub) {
  if (is.null(path_key)) {
    decypt <- function(msg, ...) stop("decryption not supported")
  } else {
    key <- config_get_key(path_key)
    decrypt <- function(msg, ...) sodium::simple_decrypt(msg, key)
  }
  pub <- config_get_key(path_pub)
  config("public",
         function(msg, ...) sodium::simple_encrypt(msg, pub),
         decrypt)
}

##' @export
##' @rdname encryptr_config
config_authenticated <- function(path_key, path_pub) {
  key <- config_get_key(path_key)
  pub <- config_get_key(path_pub)
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

as_config <- function(x) {
  if (inherits(x, "encryptr_config")) {
    x
  } else {
    make_config(x)
  }
}
