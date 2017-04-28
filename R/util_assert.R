assert_is <- function(x, what, name = deparse(substitute(x))) {
  if (!inherits(x, what)) {
    stop(sprintf("'%s' must be a %s", name,
                 paste(what, collapse = " / ")), call. = FALSE)
  }
}

assert_raw <- function(x, name = deparse(substitute(x))) {
  if (!is.raw(x) && !is.na(x)) {
    stop(sprintf("%s must be raw", name), call. = FALSE)
  }
}
