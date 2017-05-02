for (i in 1:2) {
  dest <- paste0("pair", i)
  if (!file.exists(dest)) {
    ssh_keygen(dest, password = FALSE)
  }
}

## NOTE: helper only, does not preserve visibility (c.f. encrypt)
with_connection <- function(con, expr, envir = parent.frame()) {
  on.exit(close(con))
  eval(expr, envir)
}
