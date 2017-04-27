identity_openssl <- function(path, password = NULL) {
  session_encrypt(openssl_read_key(openssl_find_key(path), password),
                  TRUE)
}

openssl_find_key <- function(path) {
  if (is.null(path)) {
    stop("not yet implemented")
  }
  if (!file.exists(path)) {
    stop("file does not exist")
  }
  if (is_directory(path)) {
    path <- file.path(path, "id_rsa")
    if (!file.exists(path)) {
      stop("did not find id_rsa within path")
    }
  }
  path
}

openssl_read_key <- function(path, password = NULL) {
  if (is.null(password)) {
    password <- function(...) {
      msg <- sprintf("Please enter password for private key %s: ", path)
      get_password_str(FALSE, msg)
    }
  }
  openssl::read_key(path, password)
}
