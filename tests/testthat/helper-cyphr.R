for (i in 1:3) {
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

sys_setenv <- function(...) {
  vars <- names(list(...))
  prev <- vapply(vars, Sys.getenv, "", NA_character_)
  Sys.setenv(...)
  prev
}

sys_resetenv <- function(old) {
  i <- is.na(old)
  if (any(i)) {
    Sys.unsetenv(names(old)[i])
  }
  if (any(!i)) {
    Sys.setenv(old[!i])
  }
}
