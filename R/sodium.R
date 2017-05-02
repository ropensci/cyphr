## NOTE: the order here (pub, key) is very important; if the wrong
## order is used you cannot decrypt things.  Unfortunately because
## sodium keys are just bytesstrings there is nothing to distinguish
## the public and private keys so this is a pretty easy mistake to
## make.
keypair_sodium <- function(pub, key, authenticated = FALSE) {
  pub <- sodium_load_key(pub)
  key <- session_encrypt(sodium_load_key(key))
  if (authenticated) {
    encrypt <- function(msg, pub, key) sodium::auth_encrypt(msg, key, pub)
    decrypt <- function(msg, pub, key) sodium::auth_decrypt(msg, key, pub)
    pack <- sodium_pack
    unpack <- sodium_unpack
  } else {
    encrypt <- function(msg, pub, key) sodium::simple_encrypt(msg, pub)
    decrypt <- function(msg, pub, key) sodium::simple_decrypt(msg, key)
    pack <- unpack <- identity
  }
  cyphr_keypair("sodium", pub, key, encrypt, decrypt, pack, unpack)
}

key_sodium <- function(key) {
  key <- session_encrypt(sodium_load_key(key))
  encrypt <- sodium::data_encrypt
  decrypt <- sodium::data_decrypt
  pack <- sodium_pack
  unpack <- sodium_unpack
  cyphr_key("sodium", key, encrypt, decrypt, pack, unpack)
}

sodium_pack <- function(x) {
  c(attr(x, "nonce", exact = TRUE), drop_attributes(x))
}

sodium_unpack <- function(x) {
  i <- seq_len(24L)
  ret <- x[-i]
  attr(ret, "nonce") <- x[i]
  ret
}

sodium_load_key <- function(x) {
  if (is.character(x)) {
    x <- read_binary(x)
  } else if (!is.raw(x)){
    stop("Expected a raw vector or a file to read from")
  }
  if (length(x) != 32L) {
    stop("Unexpected length -- expected 32 bytes")
  }
  x
}
