##' Wrapper functions for encryption.  These functions wrap
##' expressions that produce or consume a file and arrange to encrypt
##' (for producing functions) or decryprt (for consuming functions).
##' The forms with a trailing underscore (\code{encrypt_},
##' \code{decrypt_}) do not use any non-standard evaluation and may be
##' more useful for programming.
##'
##' These functions will not work for all functions.  For example
##' \code{pdf}/\code{dev.off} will create a file but we can't wrap
##' those up (yet!).  Functions that \emph{modify} a file (e.g.,
##' appending) also will not work and may cause data loss.
##'
##' @title Easy encryption and decryption
##'
##' @param expr A single expression representing a function call that
##'   would be caled for the side effect of creating or reading a
##'   file.
##'
##' @param config A \code{encryptr_config} object describing the
##'   encryption approach to use.
##'
##' @param file_arg Optional hint indicating which argument to
##'   \code{expr} is the filename.  This is done automatically for
##'   some built-in functions.
##'
##' @param envir Environment in which \code{expr} is to be evaluated.
##' @export
encrypt <- function(expr, config, file_arg=NULL, envir=parent.frame()) {
  encrypt_(substitute(expr), config, file_arg, envir)
}

##' @export
##' @rdname encrypt
decrypt <- function(expr, config, file_arg=NULL, envir=parent.frame()) {
  decrypt_(substitute(expr), config, file_arg, envir)
}

##' @export
##' @rdname encrypt
encrypt_ <- function(expr, config, file_arg=NULL, envir=parent.frame()) {
  dat <- rewrite(expr, file_arg, envir)
  on.exit(file_remove_if_exists(dat$tmp))
  res <- eval(call("withVisible", dat$expr), envir)
  encrypt_file(dat$tmp, dat$filename, config)
  if (res$visible) res$value else invisible(res$value)
}

##' @export
##' @rdname encrypt
decrypt_ <- function(expr, config, file_arg=NULL, envir=parent.frame()) {
  dat <- rewrite(expr, file_arg, envir)
  on.exit(file_remove_if_exists(dat$tmp))
  decrypt_file(dat$filename, dat$tmp, config)
  eval(dat$expr, envir)
}

file_remove_if_exists <- function(...) {
  paths <- c(...)
  ok <- file.exists(paths)
  if (any(ok)) {
    file.remove(paths[ok])
  }
}
