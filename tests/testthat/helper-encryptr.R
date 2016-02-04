## NOTE: helper only, does not preserve visibility (c.f. encrypt)
with_connection <- function(con, expr, envir=parent.frame()) {
  on.exit(close(con))
  eval(expr, envir)
}

OPENSSL_KEY <- temporary_key()
