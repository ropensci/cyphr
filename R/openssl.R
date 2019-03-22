##' Wrap a pair of openssl keys.  You should pass your private key and
##' the public key of the person that you are communicating with.
##' @title Asymmetric encryption with openssl
##'
##' @param pub An openssl public key.  Usually this will be the path
##'   to the key, in which case it may either the path to a public key
##'   or be the path to a directory containing a file
##'   \code{id_rsa.pub}.  If \code{NULL}, then your public key will be
##'   used (found via the environment variable \code{USER_PUBKEY},
##'   then \code{~/.ssh/id_rsa.pub}).  However, it is not that common
##'   to use your own public key - typically you want either the
##'   sender of a message you are going to decrypt, or the recipient
##'   of a message you want to send.
##'
##' @param key An openssl private key.  Usually this will be the path
##'   to the key, in which case it may either the path to a private
##'   key or be the path to a directory containing a file.  You may
##'   specify \code{NULL} here, in which case the environment variable
##'   \code{USER_KEY} is checked and if that is not defined then
##'   \code{~/.ssh/id_rsa} will be used.
##'
##' @param envelope A logical indicating if "envelope" encryption
##'   functions should be used.  If so, then we use
##'   \code{openssl::encrypt_envelope} and
##'   \code{openssl::decrypt_envelope}.  If \code{FALSE} then we use
##'   \code{openssl::rsa_encrypt} and \code{openssl::rsa_decrypt}.
##'   See the openssl docs for further details.  The main effect of
##'   this is that using \code{envelope = TRUE} will allow you to
##'   encrypt much larger data than \code{envelope = FALSE}; this is
##'   because openssl asymmetric encryption can only encrypt data up
##'   to the size of the key itself.
##'
##' @param password A password for the private key.  If \code{NULL}
##'   then you will be prompted interactively for your password, and
##'   if a string then that string will be used as the password (but
##'   be careful in scripts!)
##'
##' @param authenticated Logical, indicating if the result should be
##'   signed with your public key.  If \code{TRUE} then your key will
##'   be verified on decryption.  This provides tampering detection.
##' @export
##'
##' @seealso \code{\link{keypair_sodium}} for a similar function using
##'   sodium keypairs
##'
##' @examples
##'
##' # Note this uses password = FALSE for use in examples only, but
##' # this should not be done for any data you actually care about.
##'
##' # Note that the vignette contains much more information than this
##' # short example and should be referred to before using these
##' # functions.
##'
##' # Generate two keypairs, one for Alice, and one for Bob
##' path_alice <- tempfile()
##' path_bob <- tempfile()
##' cyphr::ssh_keygen(path_alice, password = FALSE)
##' cyphr::ssh_keygen(path_bob, password = FALSE)
##'
##' # Alice wants to send Bob a message so she creates a key pair with
##' # her private key and bob's public key (she does not have bob's
##' # private key).
##' pair_alice <- cyphr::keypair_openssl(pub = path_bob, key = path_alice)
##'
##' # She can then encrypt a secret message:
##' secret <- cyphr::encrypt_string("hi bob", pair_alice)
##' secret
##'
##' # Bob wants to read the message so he creates a key pair using
##' # Alice's public key and his private key:
##' pair_bob <- cyphr::keypair_openssl(pub = path_alice, key = path_bob)
##'
##' cyphr::decrypt_string(secret, pair_bob)
##'
##' # Clean up
##' unlink(path_alice, recursive = TRUE)
##' unlink(path_bob, recursive = TRUE)
keypair_openssl <- function(pub, key, envelope = TRUE, password = NULL,
                            authenticated = TRUE) {
  pub <- openssl_load_pubkey(pub)
  key <- session_encrypt(openssl_load_key(key, password))
  ## TODO: how do we do *authenticated* decryption here?  I don't know
  ## if openssl supports it?  Looks like we should wrap things up a
  ## bit so that we use openssl::signature_create and
  ## openssl::signature_verify
  pack <- openssl_pack
  unpack <- openssl_unpack
  if (authenticated) {
    if (envelope) {
      encrypt <- openssl__encrypt_envelope_auth
      decrypt <- openssl__decrypt_envelope_auth
    } else {
      encrypt <- openssl__encrypt_rsa_auth
      decrypt <- openssl__decrypt_rsa_auth
    }
  } else {
    if (envelope) {
      encrypt <- function(msg, pub, key) openssl::encrypt_envelope(msg, pub)
      decrypt <- function(msg, pub, key) openssl__decrypt_envelope(msg, key)
    } else {
      encrypt <- function(msg, pub, key) openssl::rsa_encrypt(msg, pub)
      decrypt <- function(msg, pub, key) openssl::rsa_decrypt(msg, key)
      pack <- unpack <- identity
    }
  }
  cyphr_keypair("openssl", pub, key, encrypt, decrypt, pack, unpack)
}

##' Wrap an openssl symmetric (aes) key.  This can be used with the
##' functions \code{\link{encrypt_data}} and
##' \code{\link{decrypt_data}}, along with the higher level wrappers
##' \code{\link{encrypt}} and \code{\link{decrypt}}.  With a symmetric
##' key, everybody uses the same key for encryption and decryption.
##'
##' @title Symmetric encryption with openssl
##' @param key An openssl aes key (i.e., an object of class \code{aes}).
##' @param mode The encryption mode to use.  Options are \code{cbc},
##'   \code{ctr} and \code{gcm} (see the \code{openssl} package for
##'   more details)
##' @export
##' @examples
##' # Create a new key
##' key <- cyphr::key_openssl(openssl::aes_keygen())
##' key
##'
##' # With this key encrypt a string
##' secret <- cyphr::encrypt_string("my secret string", key)
##' # And decrypt it again:
##' cyphr::decrypt_string(secret, key)
key_openssl <- function(key, mode = "cbc") {
  assert_is(key, "aes")
  key <- session_encrypt(key)
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
  unpack <- openssl_unpack_symmetric(if (mode == "gcm") 12L else 16L)
  cyphr_key("openssl", key, encrypt, decrypt, pack, unpack)
}

## -- reading --

openssl_load_key <- function(path, password = NULL) {
  key_path <- openssl_find_key(path)
  if (is.null(password)) {
    password <- function(...) {
      msg <- sprintf("Please enter password for private key %s: ", key_path)
      get_password_str(FALSE, msg)
    }
  }
  openssl::read_key(key_path, password)
}

openssl_load_pubkey <- function(path) {
  openssl::read_pubkey(openssl_find_pubkey(path))
}

## -- paths --

openssl_find_key <- function(path) {
  if (is.null(path)) {
    ## NOTE: same logic as the openssl package
    path <- Sys.getenv("USER_KEY", "~/.ssh/id_rsa")
    if (!file.exists(path)) {
      stop("Did not find default ssh private key at ", path)
    }
  }
  if (!file.exists(path)) {
    stop("Private key does not exist at ", path)
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
    ## NOTE: almost same logic as the openssl package (but without the
    ## automatic derivation bit because that would require loading the
    ## private key which would trigger a password request).
    path <- Sys.getenv("USER_PUBKEY", "~/.ssh/id_rsa.pub")
    if (!file.exists(path)) {
      stop("Did not find default ssh public key at ", path)
    }
  }
  if (!file.exists(path)) {
    stop("Public key does not exist at ", path)
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

openssl__encrypt_envelope_auth <- function(msg, pub, key) {
  dat <- openssl::encrypt_envelope(msg, pub)
  dat$signature <- openssl::signature_create(msg, openssl::sha256, key)
  dat
}

openssl__decrypt_envelope_auth <- function(x, pub, key) {
  msg <- openssl::decrypt_envelope(x$data, x$iv, x$session, key)
  openssl_verify(msg, x$signature, pub)
  msg
}

openssl__encrypt_rsa_auth <- function(msg, pub, key) {
  dat <- list(data = openssl::rsa_encrypt(msg, pub))
  dat$signature <- openssl::signature_create(msg, openssl::sha256, key)
  dat
}

openssl__decrypt_rsa_auth <- function(x, pub, key) {
  msg <- openssl::rsa_decrypt(x$data, key)
  openssl_verify(msg, x$signature, pub)
  msg
}

openssl_verify <- function(msg, signature, pub) {
  if (is.null(signature)) {
    stop("Signature missing for encrypyted data - refusing to decrypt")
  }
  withCallingHandlers(
    openssl::signature_verify(msg, signature, openssl::sha256, pub),
    error = function(e) {
      stop("Signatures do not match: ", e$message)
    })
}

## -- pack/unpack --
openssl_pack <- function(x) {
  serialize(x, NULL)
}

openssl_unpack <- function(x) {
  unserialize(x)
}

openssl_pack_symmetric <- function(x) {
  c(attr(x, "iv", exact = TRUE), drop_attributes(x))
}

openssl_unpack_symmetric <- function(iv_len) {
  force(iv_len)
  function(x) {
    i <- seq_len(iv_len)
    ret <- x[-i]
    attr(ret, "iv") <- x[i]
    ret
  }
}

openssl_fingerprint <- function(k) {
  as.list(k)$fingerprint
}
