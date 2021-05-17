##' Wrap a pair of sodium keys for asymmetric encryption.  You should
##' pass your private key and the public key of the person that you
##' are communicating with.
##'
##' *NOTE*: the order here (pub, key) is very important; if the
##' wrong order is used you cannot decrypt things.  Unfortunately
##' because sodium keys are just byte sequences there is nothing to
##' distinguish the public and private keys so this is a pretty easy
##' mistake to make.
##' @title Asymmetric encryption with sodium
##'
##' @param pub A sodium public key.  This is either a raw vector of
##'   length 32 or a path to file containing the contents of the key
##'   (written by [writeBin()]).
##'
##' @param key A sodium private key.  This is either a raw vector of
##'   length 32 or a path to file containing the contents of the key
##'   (written by [writeBin()]).
##'
##' @param authenticated Logical, indicating if authenticated
##'   encryption (via [sodium::auth_encrypt()] /
##'   [sodium::auth_decrypt()]) should be used.  If `FALSE`
##'   then [sodium::simple_encrypt()] /
##'   [sodium::simple_decrypt()] will be used.  The difference is
##'   that with `authenticated = TRUE` the message is signed with
##'   your private key so that tampering with the message will be
##'   detected.
##' @export
##'
##' @seealso [cyphr::keypair_openssl()] for a similar function using
##'   openssl keypairs
##'
##' @examples
##'
##' # Generate two keypairs, one for Alice, and one for Bob
##' key_alice <- sodium::keygen()
##' pub_alice <- sodium::pubkey(key_alice)
##' key_bob <- sodium::keygen()
##' pub_bob <- sodium::pubkey(key_bob)
##'
##' # Alice wants to send Bob a message so she creates a key pair with
##' # her private key and bob's public key (she does not have bob's
##' # private key).
##' pair_alice <- cyphr::keypair_sodium(pub = pub_bob, key = key_alice)
##'
##' # She can then encrypt a secret message:
##' secret <- cyphr::encrypt_string("hi bob", pair_alice)
##' secret
##'
##' # Bob wants to read the message so he creates a key pair using
##' # Alice's public key and his private key:
##' pair_bob <- cyphr::keypair_sodium(pub = pub_alice, key = key_bob)
##'
##' cyphr::decrypt_string(secret, pair_bob)
keypair_sodium <- function(pub, key, authenticated = TRUE) {
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

##' Wrap a sodium symmetric key.  This can be used with the functions
##' [cyphr::encrypt_data()] and [cyphr::decrypt_data()], along
##' with the higher level wrappers [cyphr::encrypt()] and
##' [cyphr::decrypt()].  With a symmetric key, everybody uses the
##' same key for encryption and decryption.
##'
##' @title Symmetric encryption with sodium
##' @param key A sodium key (i.e., generated with [sodium::keygen()]
##' @export
##' @examples
##' # Create a new key
##' key <- cyphr::key_sodium(sodium::keygen())
##' key
##'
##' # With this key encrypt a string
##' secret <- cyphr::encrypt_string("my secret string", key)
##' # And decrypt it again:
##' cyphr::decrypt_string(secret, key)
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
  } else if (!is.raw(x)) {
    stop("Expected a raw vector or a file to read from")
  }
  if (length(x) != 32L) {
    stop("Unexpected length -- expected 32 bytes")
  }
  x
}
