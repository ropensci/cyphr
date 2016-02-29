## Wrappers around sodium to give extremely basic load/save support
## (given there is no native file format for sodium).  These just load
## the raw data from a file (if given as a filename) or do nothing if
## given as a raw vector.  We check the length and then add some
## appropriate attributes so we know what we have loaded.
load_key_sodium <- function(x, type) {
  if (is.character(x)) {
    x <- read_binary(x)
  } else if (!is.raw(x)){
    stop("Expected a raw vector or a file to read from")
  }
  if (length(x) != 32L) {
    stop("Unexpected length -- expected 32 bytes")
  }
  class(x) <- c(type, "key_sodium")
  x
}

## Then things that we will use internally:
load_key_sodium_symmetric <- function(path_key) {
  load_key_sodium(path_key, "sodium_symmetric")
}
load_key_sodium_public <- function(path_pub) {
  load_key_sodium(path_pub, "sodium_public")
}
load_key_sodium_private <- function(path_key) {
  load_key_sodium(path_key, "sodium_private")
}

##' @export
print.key_sodium <- function(x, ...) {
  cat(sprintf("<%s key>\n", class(x)[[1L]]))
  invisible(x)
}

## This is never really used because I switched over to use rsa.
load_key_sodium_pair <- function(path_pub, path_key=NULL) {
  if (is.null(path_key)) {
    key <- NULL
  } else {
    key <- load_key_sodium(path_key, "sodium_private")
  }
  pub <- load_key_sodium(path_pub, "sodium_public")
  ret <- list(pub=pub, key=key)
  class(ret) <- c("sodium_pair", "key_pair")
  ret
}
