.onLoad <- function(libname, pkgname) {
  ## covr misses this but it is run :)
  session_key_refresh() # nocov
  rewrite_reset() # nocov
}
