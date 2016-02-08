## NOTE: helper only, does not preserve visibility (c.f. encrypt)
with_connection <- function(con, expr, envir=parent.frame()) {
  on.exit(close(con))
  eval(expr, envir)
}

temporary_key <- function(path=tempfile()) {
  ssh_keygen(path, FALSE)
}

OPENSSL_KEY <- temporary_key()
