openssl_read <- function(path) {
  if (is.null(path)) {
    ## TODO: openssl should accept password argument to my_key()
    path <- Sys.getenv("USER_KEY", "~/.ssh/id_rsa")
  } else if (is_directory(path)) {
    path <- file.path(path, "id_rsa")
    if (!file.exists(path)) {
      stop("Did not find id_rsa file at path ", path)
    }
  } else if (file.exists(path)) {
    path <- sub("([^/]+)\\.pub$", "\\1", path)
  } else {
    stop("path does not exist: ", path)
  }
  password <- function(prompt) {
    get_password(FALSE, 0, prompt)
  }
  key <- openssl::read_key(path, password)
  pub <- openssl::read_pubkey(paste0(path, ".pub"))
  list(key=key, pub=pub, path=path)
}

config_openssl <- function(path) {
  dat <- openssl_read(path)
  key <- dat$key
  pub <- dat$pub
  config(
    "openssl",
    function(msg, ...) openssl::encrypt_envelope(msg, pub),
    function(msg, ...) openssl__decrypt_envelope(msg, key))
}

openssl__decrypt_envelope <- function(x, key) {
  openssl::decrypt_envelope(x$data, x$iv, x$session, key)
}


temporary_key <- function(path=tempfile(), new=FALSE) {
  ssh_keygen <- Sys.which("ssh-keygen")
  if (ssh_keygen == "") {
    stop("Can not find ssh-keygen")
  }
  dir.create(path, FALSE, TRUE)
  dest <- file.path(path, "id_rsa")
  if (file.exists(dest)) {
    if (new) {
      stop("key already exists")
    }
  } else {
    code <-
      system2(ssh_keygen, c("-q", "-N", "''", "-f", file.path(path, "id_rsa")))
    if (code != 0L) {
      stop("Error running ssh-keygen")
    }
  }
  dest
}
