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
    pack <- openssl_pack_envelope
    unpack <- openssl_unpack_envelope
  } else {
    encrypt <- function(msg, pub, key) openssl::rsa_encrypt(msg, pub)
    decrypt <- function(msg, pub, key) openssl::rsa_decrypt(msg, key)
    pack <- unpack <- identity
  }
  cyphr_keypair("openssl", pub, key, encrypt, decrypt, pack, unpack)
}

key_openssl <- function(key, mode = "cbc") {
  ## TODO: no check here that 'key' is sane.
  if (mode == "cbc") {
    encrypt <- openssl::aes_cbc_encrypt
    decrypt <- openssl::aes_cbc_decrypt
  } else if (mode == "ctr") {
    encrypt <- openssl::aes_ctr_encrypt
    decrypt <- openssl::aes_ctr_decrypt
  } else if (mode == "gcm") {
    encrypt <- openssl::aes_gcm_encrypt
    decrypt <- openssl::aes_gcm_decrypt
  } else {
    stop(sprintf("Invalid encryption mode '%s'", mode))
  }
  pack <- openssl_pack_symmetric
  unpack <- openssl_unpack_symmetric
  cyphr_key("openssl", key, encrypt, decrypt, pack, unpack)
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

## -- pack/unpack --
openssl_pack_envelope <- function(x) {
  c(x$iv, x$session, x$data)
}

openssl_unpack_envelope <- function(x) {
  list(iv = x[1L:16L],
       session = x[17L:272L],
       data = x[-seq_len(272L)])
}

openssl_pack_symmetric <- function(x) {
  c(attr(x, "iv", exact = TRUE), drop_attributes(x))
}

openssl_unpack_symmetric <- function(x) {
  i <- seq_len(16L)
  ret <- x[-i]
  attr(ret, "iv") <- x[i]
  ret
}
