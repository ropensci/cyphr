keypair_openssl <- function(pub, key, envelope = TRUE, password = NULL) {
  pub <- openssl_load_pubkey(pub)
  key <- openssl_load_key(key, password)
  ## TODO: how do we do *authenticated* decryption here?  I don't know
  ## if openssl supports it?  Looks like we should wrap things up a
  ## bit so that we use openssl::signature_create and
  ## openssl::signature_verify
  if (envelope) {
    encrypt <- function(msg, pub, key) openssl::encrypt_envelope(msg, pub)
    decrypt <- function(msg, pub, key) openssl__decrypt_envelope(msg, key)
  } else {
    encrypt <- function(msg, pub, key) openssl::rsa_encrypt(msg, pub)
    decrypt <- function(msg, pub, key) openssl::rsa_decrypt(msg, key)
  }
  cyphr_keypair("openssl", pub, key, encrypt, decrypt)
}

## -- reading --

openssl_load_key <- function(path, password = NULL) {
  if (is.null(password)) {
    password <- function(...) {
      msg <- sprintf("Please enter password for private key %s: ", path)
      get_password_str(FALSE, msg)
    }
  }
  openssl::read_key(openssl_find_key(path), password)
}

openssl_load_pubkey <- function(path) {
  openssl::read_pubkey(openssl_find_pubkey(path))
}

## -- paths --

openssl_find_key <- function(path) {
  if (is.null(path)) {
    ## The logic for what to search through is pretty nasty.
    stop("not yet implemented")
  }
  if (!file.exists(path)) {
    stop("file does not exist")
  }
  if (is_directory(path)) {
    path <- file.path(path, "id_rsa")
    if (!file.exists(path)) {
      stop("did not find id_rsa within path")
    }
  }
  path
}

## It's possible that we should always require a full file here?
openssl_find_pubkey <- function(path) {
  if (is.null(path)) {
    ## The logic for what to search through is pretty nasty.
    stop("not yet implemented")
  }
  if (!file.exists(path)) {
    stop("file does not exist")
  }
  if (is_directory(path)) {
    path <- file.path(path, "id_rsa.pub")
    if (!file.exists(path)) {
      stop("did not find id_rsa.pub within path")
    }
  }
  path
}

## -- utilities --

openssl__decrypt_envelope <- function(x, key) {
  openssl::decrypt_envelope(x$data, x$iv, x$session, key)
}
