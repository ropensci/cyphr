##' Encrypt and decrypt raw data, objects, strings and files.  The
##' core functions here are \code{encrypt_data} and
##' \code{decrypt_data} which take raw data and decrypt it, writing
##' either to file or returning a raw vector.  The other functions
##' encrypt and decrypt arbitrary R objects (\code{encrypt_object},
##' \code{decrypt_object}), strings (\code{encrypt_string},
##' \code{decrypt_string}) and files (\code{encrypt_file},
##' \code{decrypt_file}).
##'
##' @title Encrypt and decrypt data and other things
##'
##' @param data (for \code{encrypt_data}, \code{decrypt_data},
##'   \code{decrypt_object}, \code{decrypt_string}) a raw vector with
##'   the data to be encrypted or decrypted.  For the decryption
##'   functions this must be data derived by encrypting something or
##'   you will get an error.
##'
##' @param object (for \code{encrypt_object}) an arbitrary R object to
##'   encrypt.  It will be serialised to raw first (see
##'   \code{\link{serialize}}).
##'
##' @param string (for \code{encrypt_string}) a scalar character
##'   vector to encrypt.  It will be converted to raw first with
##'   \code{\link{charToRaw}}.
##'
##' @param path (for \code{encrypt_file}) the name of a file to
##'   encrypt.  It will first be read into R as binary (see
##'   \code{\link{readBin}}).
##'
##' @param dest The destination filename for the encrypted or
##'   decrypted data, or \code{NULL} to return a raw vector.  This is
##'   not used by \code{decrypt_object} or \code{decrypt_string} which
##'   always return an object or string.
##'
##' @param config A \code{encryptr_config} object describing the
##'   encryption approach to use.
##' @export
##' @examples
##' key <- sodium::keygen()
##' cfg <- config_sodium_symmetric(key)
##' # Some super secret data we want to encrypt:
##' x <- runif(10)
##' # Convert the data into a raw vector:
##' data <- serialize(x, NULL)
##' data
##' # Encrypt the data; without the key above we will never be able to
##' # decrypt this.
##' data_enc <- encrypt_data(data, NULL, cfg)
##' data_enc
##' # Our random numbers:
##' unserialize(decrypt_data(data_enc, NULL, cfg))
##' # Same as the never-encrypted version:
##' x
##'
##' # This can be achieved more easily using `encrypt_object`:
##' data_enc <- encrypt_object(x, NULL, cfg)
##' identical(decrypt_object(data_enc, cfg), x)
##'
##' # Encrypt strings easily:
##' str_enc <- encrypt_string("secret message", NULL, cfg)
##' str_enc
##' decrypt_string(str_enc, cfg)
encrypt_data <- function(data, dest, config) {
  if (!is.raw(data)) {
    stop("Expected a raw vector; consider serialize(data, NULL)")
  }
  config <- make_config(config)
  res <- pack_data(config$encrypt(data))
  if (is.null(dest)) {
    res
  } else {
    writeBin(res, dest)
  }
}

##' @export
##' @rdname encrypt_data
encrypt_object <- function(object, dest, config) {
  encrypt_data(serialize(object, NULL), dest, config)
}

##' @export
##' @rdname encrypt_data
encrypt_string <- function(string, dest, config) {
  if (!(is.character(string) && length(string) == 1L)) {
    stop("'string' must be a scalar character")
  }
  encrypt_data(charToRaw(string), dest, config)
}

##' @export
##' @rdname encrypt_data
encrypt_file <- function(path, dest, config) {
  encrypt_data(read_binary(path), dest, config)
}

##' @export
##' @rdname encrypt_data
decrypt_data <- function(data, dest, config) {
  config <- make_config(config)
  res <- config$decrypt(unpack_data(data))
  if (is.null(dest)) {
    res
  } else {
    writeBin(res, dest)
  }
}

##' @export
##' @rdname encrypt_data
decrypt_object <- function(data, config) {
  unserialize(decrypt_data(data, NULL, config))
}

##' @export
##' @rdname encrypt_data
decrypt_string <- function(data, config) {
  rawToChar(decrypt_data(data, NULL, config))
}

##' @export
##' @rdname encrypt_data
decrypt_file <- function(path, dest, config) {
  decrypt_data(read_binary(path), dest, config)
}

## A little convention for keeping the nonce and the cipher together;
## the first byte will be the length of the nonce (limited to 255) so
## that we store:
##   <type> <length>  <nonce>    <encrypted thing>
##   1 byte
##   <type> <length>  <nonce>    <encrypted thing>
##   0      1 byte    n bytes    rest of file
##   <type> <id>      <session>  <encrypted thing>
##   1      16 bytes  256 bytes  rest of file
##
## This ensures we can hold all the bits required for encryption
## together but pull them back apart when needed for decryption.
FORMAT_SODIUM <- as.raw(0L)
FORMAT_OPENSSL <- as.raw(1L)

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
  } else {
    stop("Invalid input")
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
