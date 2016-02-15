## TODO: which functions here are the API bits?
##
##  Functions for loading keys seems sensible, but I'm not sure what
##  the best thing to do here is.

key_sodium_symmetric <- function(path_key) {
  load_key_sodium(path_key, "sodium_symmetric", 32L)
}

## make this pair_sodium?
key_sodium_public <- function(path_pub, path_key=NULL) {
  if (is.null(path_key)) {
    key <- NULL
  } else {
    key <- load_key_sodium(path_key, "sodium_private", 32L)
  }
  pub <- load_key_sodium(path_pub, "sodium_public", 32L)
  ret <- list(pub=pub, key=key)
  class(ret) <- c("sodium_pair", "key_pair")
  ret
}

##' @export
print.key_pair <- function(x, ...) {
  cat(sprintf("<%s key pair>\n", class(x)[[1L]]))
  invisible(x)
}

##' @export
print.key_sodium <- function(x, ...) {
  cat(sprintf("<%s key>\n", class(x)[[1L]]))
  invisible(x)
}

make_config <- function(x, ...) {
  UseMethod("make_config")
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

load_key_sodium <- function(x, type, len=32L) {
  if (is.character(x)) {
    x <- read_binary(x)
  } else if (!is.raw(x)){
    stop("Expected a raw vector or a file to read from")
  }
  if (length(x) != len) {
    stop("Unexpected length")
  }
  class(x) <- c(type, "key_sodium")
  x
}
