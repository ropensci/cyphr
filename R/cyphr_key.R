## For a symmetric key everyone has the same key
##
## encrypt and decrypt have signature (msg, key) -> raw
cyphr_key <- function(type, key, encrypt, decrypt, pack, unpack) {
  force(pack)
  force(unpack)
  assert_is(key, "function")
  ret <- list(type = type,
              key = key,
              encrypt = function(msg) pack(encrypt(msg, key())),
              decrypt = function(msg) decrypt(unpack(msg), key()))
  class(ret) <- "cyphr_key"
  ret
}

## If we want to *send* something to somewhere we encrypt a message
## with *their* public key and *our* private key
##
## If we want to *read* something from somewhere we decrypt a message
## with *thier* public key and *our* private key
##
## encrypt and decrypt have signature (msg, pub, key) -> raw
cyphr_keypair <- function(type, pub, key, encrypt, decrypt, pack, unpack) {
  force(pack)
  force(unpack)
  assert_is(key, "function")
  ret <- list(type = type,
              pub = pub,
              key = key,
              encrypt = function(msg) pack(encrypt(msg, pub, key())),
              decrypt = function(msg) decrypt(unpack(msg), pub, key()))
  class(ret) <- c("cyphr_keypair", "cyphr_key")
  ret
}

##' @export
print.cyphr_key <- function(x, ...) {
  cat(sprintf("<cyphr_key: %s>\n", x$type))
  invisible(x)
}

##' @export
print.cyphr_keypair <- function(x, ...) {
  cat(sprintf("<cyphr_keypair: %s>\n", x$type))
  invisible(x)
}
