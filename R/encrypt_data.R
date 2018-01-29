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
##' @param key A \code{cyphr_key} or \code{cyphr_key} object
##'   describing the encryption approach to use.
##' @export
##' @examples
##' key <- key_sodium(sodium::keygen())
##' # Some super secret data we want to encrypt:
##' x <- runif(10)
##' # Convert the data into a raw vector:
##' data <- serialize(x, NULL)
##' data
##' # Encrypt the data; without the key above we will never be able to
##' # decrypt this.
##' data_enc <- encrypt_data(data, key)
##' data_enc
##' # Our random numbers:
##' unserialize(decrypt_data(data_enc, key))
##' # Same as the never-encrypted version:
##' x
##'
##' # This can be achieved more easily using `encrypt_object`:
##' data_enc <- encrypt_object(x, key)
##' identical(decrypt_object(data_enc, key), x)
##'
##' # Encrypt strings easily:
##' str_enc <- encrypt_string("secret message", key)
##' str_enc
##' decrypt_string(str_enc, key)
encrypt_data <- function(data, key, dest = NULL) {
  if (!is.raw(data)) {
    stop("Expected a raw vector; consider serialize(data, NULL)")
  }
  assert_is(key, "cyphr_key")
  res <- key$encrypt(data)
  if (is.null(dest)) {
    res
  } else {
    writeBin(res, dest)
  }
}

##' @export
##' @rdname encrypt_data
##' @param rds_version RDS serialisation version to use (see
##'   \code{\link{serialize}}.  The default in R version 3.3 and below
##'   is version 2 - in the R 3.4 series version 3 was introduced and
##'   is becoming the default.  Version 3 format serialisation is not
##'   understood by older versions so if you need to exchange data
##'   with older R versions, you will need to use \code{rds_version =
##'   2}.  The default argument here (\code{NULL}) will ensure the
##'   same serialisation is used as R would use by default.
encrypt_object <- function(object, key, dest = NULL, rds_version = NULL) {
  encrypt_data(serialize(object, NULL, version = rds_version), key, dest)
}

##' @export
##' @rdname encrypt_data
encrypt_string <- function(string, key, dest = NULL) {
  if (!(is.character(string) && length(string) == 1L)) {
    stop("'string' must be a scalar character")
  }
  encrypt_data(charToRaw(string), key, dest)
}

##' @export
##' @rdname encrypt_data
encrypt_file <- function(path, key, dest = NULL) {
  encrypt_data(read_binary(path), key, dest)
}

##' @export
##' @rdname encrypt_data
decrypt_data <- function(data, key, dest = NULL) {
  assert_is(key, "cyphr_key")
  if (is.character(data)) {
    if (file.exists(data)) {
      data <- read_binary(data)
    } else {
      stop("If given as a character string, data must be a file that exists")
    }
  }
  res <- key$decrypt(data)
  if (is.null(dest)) {
    res
  } else {
    writeBin(res, dest)
  }
}

##' @export
##' @rdname encrypt_data
decrypt_object <- function(data, key) {
  unserialize(decrypt_data(data, key, NULL))
}

##' @export
##' @rdname encrypt_data
decrypt_string <- function(data, key) {
  rawToChar(decrypt_data(data, key, NULL))
}

##' @export
##' @rdname encrypt_data
decrypt_file <- function(path, key, dest = NULL) {
  decrypt_data(read_binary(path), key, dest)
}
