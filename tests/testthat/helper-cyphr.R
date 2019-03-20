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
    do.call("Sys.setenv", as.list(old[!i]))
  }
}

skip_if_no_ssh_keygen <- function() {
  if (nzchar(Sys.which("ssh-keygen"))) {
    return()
  }
  testthat::skip("ssh-keygen not found")
}


unzip_reference <- function(zip) {
  tmp <- tempfile()
  res <- utils::unzip(zip, exdir = tmp)
  files <- dir(tmp)
  stopifnot(length(files) == 1)
  file.path(tmp, files)
}
