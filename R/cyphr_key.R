## For a symmetric key everyone has the same key
cyphr_key <- function(type, key, encrypt, decrypt, session) {
  ret <- list(type = type,
              ## key = key,
              encrypt = encrypt,
              decrypt = decrypt %||% cant_decrypt,
              session = session)
  class(ret) <- "cyphr_key"
  ret
}

## If we want to *send* something to somewhere we encrypt a message
## with *their* public key and *our* private key
##
## If we want to *read* something from somewhere we decrypt a message
## with *thier* public key and *our* private key
cyphr_keypair <- function(type, pub, key, encrypt, decrypt) {
  ret <- list(type = type,
              ## pub = pub,
              ## key = key,
              encrypt = encrypt,
              decrypt = decrypt %||% cant_decrypt,
              session = session)
  class(ret) <- c("cyphr_keypair", "cyphr_key")
  ret
}

##' @export
print.cyphr_key <- function(x, ...) {
  cat(sprintf("<cyphr: %s>\n", x$type))
  invisible(x)
}

##' @export
print.cyphr_keypair <- function(x, ...) {
  cat(sprintf("<%s key pair>\n", class(x)[[1L]]))
  invisible(x)
}

cant_decrypt <- function(msg, ...) {
  stop("decryption not supported")
}
