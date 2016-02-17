## This is a *giant* hack, and significantly more tricky to get right
## than I would have thought it should be.  The aim is to take an
## expression like:
##
##   read.csv("myfile", stringsAsFactors=FALSE)
##   saveRDS(data, file="myfile")

rewrite <- function(expr, file_arg=NULL, envir=parent.frame(),
                    filename=tempfile()) {
  if (!is.call(expr)) {
    stop("Expected call")
  }
  dat <- find_function(expr[[1]], envir)

  x <- db_lookup(dat$name, dat$ns, file_arg)
  ## There's a giant workaround here for write.csv & write.csv2 which
  ## pass all their arguments to write.table with a little rewriting.
  ##
  ## There might be a more general form in here where the filename is
  ## part of a dots argument and fn could be the pointer to the
  ## underlying function that will take the dots.
  defn <- if (is.null(x$fn)) dat$defn else x$fn
  norm <- match.call(defn, expr, expand.dots=TRUE)

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
                   x$arg, paste(deparse(expr), collapse=" ")))
    }
  }
  orig <- eval(norm[[i]], envir)
  norm[[i]] <- filename
  list(filename=orig,
       tmp=filename,
       expr=norm)
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
    defn <- get(as.character(name), envir=envir, mode="function")
    env <- environment(defn)
    if (isNamespace(env)) {
      ns <- getNamespaceName(env)
      ok <- exists(name, env, inherits=FALSE) &&
        identical(defn, getExportedValue(ns, name))
      if (!ok) {
        ## OK, this is ugly and should be memoised.  We need to scan
        ## through all the functions in the given environment and
        ## check to see which is the correct one.
        for (i in names(env)) {
          if (identical(defn, get0(i, env, inherits=FALSE))) {
            name <- i
            break
          }
        }
      }
    } else {
      ns <- ""
    }
  } else { ## need to handle is.function here, still; it will be slower.
    stop("Confused.")
  }
  list(name=name, defn=defn, ns=ns)
}

## Need to create a little database of known filename arguments to
## widely used functions.  Getting a full list here is going to be a
## little hard, but so long as this is extensible it doesn't much
## matter.
##
## What seems to be required is that we know *where* to find a
## function.  So we'll get a definition which is the function as
## passed in.  The expression might be:
##   base::readRDS
## in which case we'll know that the namespace is base, or it'd be
##   readRDS
## in which case 'get' will hopefully identify the correct namespace
## by being the enclosing namespace.  That's prone to abuse with
##   environment(foo) <- as.environment("package:bar")
## but should suffice for now.  The solution would be to replace 'get'
## with something that manually traverses the environments, which I
## implemented in rrqueue.
##
## This should be implemented as a data.frame I think; that'd be heaps
## easier to extend, especially if it compiles at load (csv -> dat or
## store in sysdata).
##
## making this extensible probably requires having additional elements
## that are added to this list when the db call is run; those could
## come from a registering process easily enough (e.g., during onLoad());
##   add_to_db(package, name, arg)
db <- function() {
  f <- function(name, arg, package, fn=NA_character_) {
    c(name=name, arg=arg, package=package, fn=fn)
  }
  dat <-
    rbind(f("readLines",   "con",      "base"),
          f("writeLines",  "con",      "base"),
          f("readRDS",     "file",     "base"),
          f("saveRDS",     "file",     "base"),
          f("read.table",  "file",     "utils"),
          f("write.table", "file",     "utils"),
          f("read.csv",    "file",     "utils"),
          f("write.csv",   "file",     "utils", "utils::write.table"),
          f("read.csv2",   "file",     "utils"),
          f("write.csv2",  "file",     "utils", "utils::write.table"),
          f("read.delim",  "file",     "utils"),
          f("read.delim2", "file",     "utils"))
  ## NOTE: graphics devices will take work to get working because it's
  ## at device *close* that the encryption should happen.  This is
  ## easy enough to do with dev.off() though the interface would look
  ## better if it was around the pdf call.
  ##
  ## Another option would be to implement enough of a stub around
  ## devices?  Or we could take the loggr approach and add hooks
  ## within dev.off() that look for registered devices.
  ##
  ## Similar things would be needed for knitr output where a hook
  ## needs to be added after figure generation.
  as.data.frame(dat, stringsAsFactors=FALSE)
}

db_lookup <- function(name, package, arg) {
  db <- db()
  i <- which(db$package == package & db$name == name)
  if (length(i) > 1L) {
    ## Clean this on entry.
    stop("Duplicate database entries, stopping")
  } else if (length(i) == 1L) {
    ret <- as.list(db[i, ])
    if (is.na(ret$fn)) {
      ret$fn <- NULL
    } else {
      tmp <- strsplit(ret$fn, "::", fixed=TRUE)[[1]]
      ret$fn <- args(getExportedValue(tmp[[1]], tmp[[2]]))
    }
    if (!is.null(arg)) {
      ret$arg <- arg
    }
    ret
  } else if (is.null(arg)) {
    nm <- if (package == "") name else paste0(package, "::", name)
    stop(sprintf("Function %s not found in database", nm))
  } else {
    list(arg=arg)
  }
}
