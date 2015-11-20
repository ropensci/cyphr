##' Encrypt and decrypt a file.
##' @title Encrypt and decrypt a file
##'
##' @param src The source filename (clear file for
##'   \code{encrypt_file}, encrypted file for \code{decrypt_file}).
##'
##' @param dest The destination filename (encrypted file for
##'   \code{encrypt_file}, decrypted file for \code{decrypt_file}).
##'   Can be the same as \code{src} in which case the file will be
##'   overwritten without warning.
##'
##' @param config A \code{encryptr_config} object describing the
##'   encryption approach to use.
##'
##' @export
encrypt_file <- function(src, dest, config) {
  res <- config$encrypt(read_binary(src))
  writeBin(add_nonce(res), dest)
}
##' @export
##' @rdname encrypt_file
decrypt_file <- function(src, dest, config) {
  res <- split_nonce(read_binary(src))
  writeBin(config$decrypt(res), dest)
}

## A little convention for keeping the nonce and the cipher together;
## the first byte will be the length of the nonce (limited to 255) so
## that we store:
##   <length>  <nonce>  <encrypted thing>
##   1 byte    n bytes  rest of file
add_nonce <- function(x) {
  nonce <- attr(x, "nonce")
  len <- length(nonce)
  if (len > 255) { # i.e., ff
    stop("nonce too long!")
  }
  c(as.raw(len), nonce, x)
}
split_nonce <- function(dat) {
  len <- as.integer(dat[[1]])
  nonce <- dat[seq_len(len) + 1L]
  x <- dat[-seq_len(len + 1L)]
  attr(x, "nonce") <- nonce
  x
}
