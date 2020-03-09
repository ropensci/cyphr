.onLoad <- function(libname, pkgname) { # nolint
  ## covr misses this but it is run :)
  session_key_refresh() # nocov
  rewrite_reset() # nocov
  data_pkg_init() # nocov
}
