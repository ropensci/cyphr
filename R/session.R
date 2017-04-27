## This exists so that we never actually store private keys in objects
## that might be serialized.  Instead, we pass them around in an
## encrypted form and decrypt on use.  This is done with a session
## key, so that any key serialised out from one session will expire in
## the next (or rather, will not be decryptable in a second session).
## The session key ks stored in the package global 'session$key' which
## is generated on startup (so this is not protected from *users*
## getting the key out, but then they know their own key already of
## course).
session <- new.env(parent = emptyenv())
session_key_refresh <- function() {
  session$key <- sodium::keygen()
}

session_encrypt <- function(key, force_object = FALSE) {
  if (is.raw(key) && !force_object) {
    data <- sodium::data_encrypt(key, session$key)
    function() {
      sodium::data_decrypt(data, session$key)
    }
  } else {
    data <- sodium::data_encrypt(serialize(key, NULL), session$key)
    function() {
      unserialize(sodium::data_decrypt(data, session$key))
    }
  }
}
