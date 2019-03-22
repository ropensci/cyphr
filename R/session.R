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

##' Refresh the session key, invalidating all keys created by
##' \code{\link{key_openssl}}, \code{\link{keypair_openssl}},
##' \code{\link{key_sodium}} and \code{\link{keypair_sodium}}.
##'
##' Running this function will invalidate \emph{all} keys loaded with
##' the above functions.  It should not be needed very often.
##'
##' @title Refresh the session key
##' @export
##'
##' @examples
##'
##' # Be careful - if you run this then all keys loaded from file will
##' # no longer work until reloaded
##' if (FALSE) {
##'   cyphr::session_key_refresh()
##' }
session_key_refresh <- function() {
  session$key <- sodium::keygen()
}

session_encrypt <- function(key) {
  if (is.raw(key) && identical(class(key), "raw")) {
    data <- session_encrypt_key_data(key)
    rm(key)
    function() {
      session_decrypt_key(data)
    }
  } else {
    data <- session_encrypt_key_data(serialize(key, NULL))
    rm(key)
    function() {
      unserialize(session_decrypt_key(data))
    }
  }
}

session_encrypt_key_data <- function(key) {
  sodium::data_encrypt(key, session$key)
}

session_decrypt_key <- function(data) {
  tryCatch(
    sodium::data_decrypt(data, session$key),
    error = function(e) {
      stop("Failed to decrypt key as session key has changed",
           call. = FALSE)
    })
}
