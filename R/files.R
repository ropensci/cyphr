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
  writeBin(pack_data(res), dest)
}
##' @export
##' @rdname encrypt_file
decrypt_file <- function(src, dest, config) {
  res <- unpack_data(read_binary(src))
  writeBin(config$decrypt(res), dest)
}

## A little convention for keeping the nonce and the cipher together;
## the first byte will be the length of the nonce (limited to 255) so
## that we store:
##   <type> <length>  <nonce>  <encrypted thing>
##   1 byte
##   <type> <length>  <nonce>  <encrypted thing>
##   0       1 byte    n bytes  rest of file
##   <type> <id>      <session>  <encrypted thing>
##   1       16 bytes  256 bytes  rest of file

FORMAT_SODIUM <- as.raw(0L)
FORMAT_OPENSSL <- as.raw(1L)

## If the length is zero, assume openssl (this might change to an
## explicit flag later, but not sure).
pack_data <- function(x) {
  if (is.raw(x)) { # sodium
    nonce <- attr(x, "nonce")
    len <- length(nonce)
    if (len > 255) { # i.e., ff
      stop("nonce too long!")
    }
    c(FORMAT_SODIUM, as.raw(len), nonce, x)
  } else if (is.list(x)) { # openssl
    c(FORMAT_OPENSSL, as.raw(0L), x$iv, x$session, x$data)
  }
}

unpack_data <- function(dat) {
  type <- dat[[1L]]
  if (type == FORMAT_SODIUM) {
    len <- as.integer(dat[[2L]])
    nonce <- dat[seq_len(len) + 2L]
    x <- dat[-seq_len(len + 2L)]
    attr(x, "nonce") <- nonce
    x
  } else if (type == FORMAT_OPENSSL) { # openssl
    list(iv=dat[seq_len(16L) + 2L],
         session=dat[seq_len(256L) + 18L],
         data=dat[-seq_len(18L + 256L)])
  } else {
    stop("Invalid input")
  }
}
