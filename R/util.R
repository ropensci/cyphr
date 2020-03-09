get_password_str <- function(verify, prompt) {
  pw <- get_pass(prompt)
  if (verify && !identical(get_pass("Verify passphrase: "), pw)) {
    stop("Passwords do not match", call. = FALSE)
  }
  pw
}

## Wrapper for testing
get_pass <- function(prompt) {
  getPass::getPass(prompt, TRUE) # nocov
}

is_directory <- function(x) {
  file.exists(x) && file.info(x, extra_cols = FALSE)[["isdir"]]
}

sys_which <- function(name) {
  path <- Sys.which(name)
  if (path == "") {
    stop(sprintf("Can not find '%s'", name))
  }
  path
}

read_binary <- function(filename) {
  if (is_connection(filename)) {
    read_binary_loop(filename, 1024L)
  } else {
    readBin(filename, raw(), file.size(filename))
  }
}

read_binary_loop <- function(con, n) {
  res <- raw()
  repeat {
    tmp <- readBin(con, raw(), n)
    if (length(tmp) == 0L) {
      break
    } else {
      res <- c(res, tmp)
    }
  }
  res
}

is_connection <- function(x) {
  inherits(x, "connection")
}

drop_attributes <- function(x) {
  attributes(x) <- NULL
  x
}

file_remove_if_exists <- function(...) {
  paths <- c(...)
  ok <- file.exists(paths)
  if (any(ok)) {
    file.remove(paths[ok])
  }
}

tempfile_keep_ext <- function(filename, local = FALSE) {
  if (!is.character(filename)) {
    tempfile()
  } else {
    dir <- if (local) dirname(filename) else tempdir()
    r <- regexpr("\\.([[:alnum:]]+)$", filename)
    base <- basename(filename)
    if (r > 0) {
      ext <- substr(base, r, nchar(base))
      base <- substr(base, 1, r - 1L)
    } else {
      base <- base
      ext <- ""
    }
    tempfile(base, dir, ext)
  }
}

bin2str <- function(x, sep = "::") {
  as.character(x, sep)
}
str2bin <- function(x) {
  sodium::hex2bin(x)
}

find_file_descend <- function(target, start = ".", limit = "/") {
  root <- normalizePath(limit, mustWork = TRUE)
  start <- normalizePath(start, mustWork = TRUE)

  f <- function(path) {
    if (file.exists(file.path(path, target))) {
      return(path)
    }
    if (normalizePath(path, mustWork = TRUE) == root) {
      return(NULL)
    }
    parent <- normalizePath(file.path(path, ".."))
    if (parent == path) {
      return(NULL)
    }
    Recall(parent)
  }
  ret <- f(start)
  if (!(is.null(ret))) {
    ret <- normalizePath(ret, mustWork = TRUE)
  }
  ret
}

## Replace with ask once it's on CRAN?
prompt_confirm <- function(msg = "continue?", valid = c(n = FALSE, y = TRUE),
                           default = names(valid)[[1]]) {
  valid_values <- names(valid)
  msg <- sprintf("%s [%s]: ", msg,
                 paste(c(toupper(default), setdiff(valid_values, default)),
                       collapse = "/"))
  repeat {
    x <- trimws(tolower(read_line(msg)))
    if (!nzchar(x)) {
      x <- default
    }
    if (x %in% valid_values) {
      return(valid[[x]])
    } else {
      cat("Invalid choice\n")
    }
  }
}

## Factoring out so that it is mockable:
read_line <- function(prompt) {
  readline(prompt = prompt) # nocov
}

`%||%` <- function(a, b) { # nolint
  if (is.null(a)) b else a
}

cyphr_file <- function(...) {
  system.file(..., package = "cyphr", mustWork = TRUE)
}

file_copy <- function(...) {
  stopifnot(file.copy(...))
}
