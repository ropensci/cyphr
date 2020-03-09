##' Wrapper functions for encryption.  These functions wrap
##' expressions that produce or consume a file and arrange to encrypt
##' (for producing functions) or decrypt (for consuming functions).
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
##'   would be called for the side effect of creating or reading a
##'   file.
##'
##' @param key A \code{cyphr_key} object describing the
##'   encryption approach to use.
##'
##' @param file_arg Optional hint indicating which argument to
##'   \code{expr} is the filename.  This is done automatically for
##'   some built-in functions.
##'
##' @param envir Environment in which \code{expr} is to be evaluated.
##' @export
##' @examples
##' # To do anything we first need a key:
##' key <- cyphr::key_sodium(sodium::keygen())
##'
##' # Encrypted write.csv - note how any number of arguments to
##' # write.csv will be passed along
##' path <- tempfile(fileext = ".csv")
##' cyphr::encrypt(write.csv(iris, path, row.names = FALSE), key)
##'
##' # The new file now exists
##' file.exists(path)
##'
##' # ...but it cannot be read with read.csv!
##' try(read.csv(path, stringsAsFactors = FALSE))
##'
##' # Wrap the read.csv call with cyphr::decrypt()
##' dat <- cyphr::decrypt(read.csv(path, stringsAsFactors = FALSE), key)
##' head(dat)
##'
##' file.remove(path)
##'
##' # If you have a function that is not supported you can specify the
##' # filename argument directly.  For example, with "write.dcf" the
##' # filename argument is called "file"; we can pass that along
##' path <- tempfile()
##' cyphr::encrypt(write.dcf(list(a = 1), path), key, file_arg = "file")
##'
##' # Similarly for decryption:
##' cyphr::decrypt(read.dcf(path), key, file_arg = "file")
encrypt <- function(expr, key, file_arg = NULL, envir = parent.frame()) {
  encrypt_(substitute(expr), key, file_arg, envir)
}

##' @export
##' @rdname encrypt
decrypt <- function(expr, key, file_arg = NULL, envir = parent.frame()) {
  decrypt_(substitute(expr), key, file_arg, envir)
}

##' @export
##' @rdname encrypt
encrypt_ <- function(expr, key, file_arg = NULL, envir = parent.frame()) {
  dat <- rewrite(expr, file_arg, envir)
  on.exit(file_remove_if_exists(dat$tmp))
  res <- eval(call("withVisible", dat$expr), envir)
  encrypt_file(dat$tmp, key, dat$filename)
  if (res$visible) res$value else invisible(res$value)
}

##' @export
##' @rdname encrypt
decrypt_ <- function(expr, key, file_arg = NULL, envir = parent.frame()) {
  dat <- rewrite(expr, file_arg, envir)
  on.exit(file_remove_if_exists(dat$tmp))
  decrypt_file(dat$filename, key, dat$tmp)
  eval(dat$expr, envir)
}

rewrite <- function(expr, file_arg = NULL, envir = parent.frame(),
                    filename = NULL) {
  if (!is.call(expr)) {
    stop("Expected call")
  }
  dat <- find_function(expr[[1]], envir)

  x <- db_lookup(dat$ns, dat$name, file_arg)
  ## There's a giant workaround here for write.csv & write.csv2 which
  ## pass all their arguments to write.table with a little rewriting.
  ##
  ## There might be a more general form in here where the filename is
  ## part of a dots argument and fn could be the pointer to the
  ## underlying function that will take the dots.
  defn <- if (is.null(x$fn)) dat$defn else x$fn
  norm <- match.call(defn, expr, expand.dots = TRUE)

  ## NOTE: don't need to worry about > 1 match because match.call will
  ## do that for us.
  i <- match(x$arg, names(norm))
  if (is.na(i)) {
    ## Second shot; could be a default argument to the function (this
    ## doesn't happen in any of the built-in functions so far, but see
    ## the tests).
    ##
    ## But then there are other issues throughout here; I often use a
    ## pattern where the filename is NULL in the argument lists and
    ## then filled in during the function body.
    ##
    ## Another option here could be to replace the 'filename' objects
    ## with active binding functions that are dynamically bound back
    ## to the environment here?  But that still requires some serious
    ## faff (e.g. including trace).
    ##
    ## In that case we would not have to rewrite anything and just
    ## determine what the argument is.
    if (x$arg %in% names(formals(defn))) {
      ## NOTE: this is the *wrong environment*; what we really need to
      ## do is evaluate this function in the calling function but
      ## that's hard to the point of being impossible.  But it does
      ## mean that if there are side effects or lazy evaluation this
      ## is not going to behave appropriately.
      i <- length(norm) + 1L
      norm[[i]] <- formals(defn)[[x$arg]]
      names(norm)[[i]] <- x$arg
    } else {
      stop(sprintf("Cannot infer file argument '%s' in '%s'",
                   x$arg, paste(deparse(expr), collapse = " ")))
    }
  }
  orig <- eval(norm[[i]], envir)
  if (is.null(filename)) {
    filename <- tempfile_keep_ext(orig)
  }
  norm[[i]] <- filename
  list(filename = orig,
       tmp = filename,
       expr = norm)
}

find_function <- function(name, envir) {
  if (is.call(name)) {
    if (name[[1]] == quote(`::`)) {
      defn <- eval(name, envir)
      ns <- deparse(name[[2]])
      name <- deparse(name[[3]])
    } else {
      stop("Invalid function call for name")
    }
  } else if (is.symbol(name)) {
    name <- as.character(name)
    defn <- get(as.character(name), envir = envir, mode = "function")
    env <- environment(defn)
    if (isNamespace(env)) {
      ns <- getNamespaceName(env)
      ok <- exists(name, env, inherits = FALSE) &&
        identical(defn, getExportedValue(ns, name))
      if (!ok) {
        ## OK, this is ugly and should be memoised.  We need to scan
        ## through all the functions in the given environment and
        ## check to see which is the correct one.
        for (i in names(env)) {
          if (identical(defn, get0(i, env, inherits = FALSE))) {
            name <- i
            break
          }
        }
      }
    } else {
      ns <- ""
    }
  } else {
    ## need to handle is.function here, still; it will be slower.
    ## That might an issue with things like lapply, perhaps.
    stop("Confused.")
  }
  list(name = name, defn = defn, ns = ns)
}

## Need to create a little lookup table of known filename arguments to
## widely used functions.  Getting a full list here is going to be a
## little hard, but so long as this is extensible it doesn't much
## matter.
##
## What seems to be required is that we know *where* to find a
## function.  So we'll get a definition which is the function as
## passed in.  The expression might be:
##   > base::readRDS
## in which case we'll know that the namespace is base, or it'd be
##   > readRDS
## in which case 'get' will hopefully identify the correct namespace
## by being the enclosing namespace.  That's prone to abuse with
##   > environment(foo) <- as.environment("package:bar")
## but should suffice for now.  The solution would be to replace 'get'
## with something that manually traverses the environments, which I
## implemented in rrqueue.
##
## making this extensible probably requires having additional elements
## that are added to this list when the db call is run; those could
## come from a registering process easily enough (e.g., during
## \code{.onLoad()});
##   > rewrite_register(package, name, arg)

## NOTE: graphics devices will take work to get working because it's
## at device *close* that the encryption should happen.  This is easy
## enough to do with dev.off() though the interface would look better
## if it was around the pdf call.
##
## Another option would be to implement enough of a stub around
## devices?  Or we could take the loggr approach and add hooks within
## dev.off() that look for registered devices.
##
## Similar things would be needed for knitr output where a hook needs
## to be added after figure generation.

db <- new.env(parent = baseenv())

db_lookup <- function(package, name, arg) {
  key <- paste(package, name, sep = "::")
  if (exists(key, db)) {
    ret <- db[[key]]
    if (!is.null(ret$fn)) {
      ret$fn <- args(getExportedValue(ret$fn[[1]], ret$fn[[2]]))
    }
    if (!is.null(arg)) {
      ret$arg <- arg
    }
  } else if (is.null(arg)) {
    stop(sprintf("Rewrite rule for %s not found",
                 if (package == "") name else key))
  } else {
    ret <- list(arg = arg)
  }
  ret
}

##' Add information about argument rewriting so that they can be used
##' with \code{\link{encrypt}} and \code{\link{decrypt}}.
##'
##' If your package uses cyphr, it might be useful to add this as
##' an \code{.onLoad()} hook.
##' @title Register functions to work with encrypt/decrypt
##' @param package The name of the package with the function to
##'   support (as a scalar character).  If your function has no
##'   package (e.g., a function you are working on outside of a
##'   package, use "" as the name).
##' @param name The name of the function to support.
##' @param arg The name of the argument in the target function that
##'   refers to the file that should be encrypted or decrypted.  This
##'   is the value you would pass through to \code{file_arg} in
##'   \code{\link{encrypt}}.
##' @param fn Optional (and should be rare) argument used to work
##'   around functions that pass all their arguments through to a
##'   second function as dots.  This is how \code{read.csv} works.  If
##'   needed this function is a length-2 character vector in the form
##'   "package", "name" with the actual function that is used.  But
##'   this should be very rare!
##' @export
##' @examples
##' # The saveRDS function is already supported.  But if we wanted to
##' # support it we could look at the arguments for the function:
##' args(saveRDS)
##' # The 'file' argument is the one that refers to the filename, so
##' # we'd write:
##' cyphr::rewrite_register("base", "saveRDS", "file")
##' # It's non-API but you can see what is supported in the package by
##' # looking at
##' ls(cyphr:::db)
rewrite_register <- function(package, name, arg, fn = NULL) {
  check <- function(x, len = 1L, nm = deparse(substitute(x))) {
    if (!(is.character(x) && length(x) == len && !any(is.na(x)))) {
      if (len == 1L) {
        stop(sprintf("%s must be a non-NA scalar character", nm))
      } else {
        stop(sprintf("%s must be a character vector of length %d", nm, len))
      }
    }
  }
  check(name)
  check(arg)
  check(package)
  if (!is.null(fn)) {
    check(fn, 2L)
  }
  key <- paste(package, name, sep = "::")
  dat <- list(name = name, package = package, arg = arg, fn = fn)
  if (exists(key, db) && !isTRUE(identical(dat, db[[key]]))) {
    stop(sprintf("An entry already exists for %s and contents differ", key))
  } else {
    assign(key, dat, envir = db)
  }
}

rewrite_reset <- function() {
  rm(list = ls(db, all.names = TRUE), envir = db)
  rewrite_register("base",  "readLines",   "con")
  rewrite_register("base",  "writeLines",  "con")
  rewrite_register("base",  "readRDS",     "file")
  rewrite_register("base",  "saveRDS",     "file")
  rewrite_register("base",  "save",        "file")
  rewrite_register("base",  "load",        "file")
  rewrite_register("utils", "read.table",  "file")
  rewrite_register("utils", "write.table", "file")
  rewrite_register("utils", "read.csv",    "file")
  rewrite_register("utils", "write.csv",   "file", c("utils", "write.table"))
  rewrite_register("utils", "read.csv2",   "file")
  rewrite_register("utils", "write.csv2",  "file", c("utils", "write.table"))
  rewrite_register("utils", "read.delim",  "file")
  rewrite_register("utils", "read.delim2", "file")
  ## Other useful things
  rewrite_register("readxl",  "read_excel", "path")
  rewrite_register("readxl",  "read_xlsx",  "path")
  rewrite_register("readxl",  "read_xls",   "path")
  rewrite_register("writexl", "write_xlsx", "path")
}
