is_directory <- function(x) {
  file.exists(x) && file.info(x, FALSE)[["isdir"]]
}

bin2str <- function(x, sep="::") {
  paste(as.character(x), collapse=sep)
}
str2bin <- function(x) {
  sodium::hex2bin(x)
}

## I believe that the file size trick will always work; we look up the
## size of the file and read that many bytes from it.  No doubt there
## are endian/platform specific issues though.
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

## Replace with ask once it's on CRAN, perhaps.
prompt_confirm <- function(msg="continue?", valid=c(n=FALSE, y=TRUE),
                           default=names(valid)[[1]]) {
  valid_values <- names(valid)
  msg <- sprintf("%s [%s]: ", msg,
                 paste(c(toupper(default), setdiff(valid_values, default)),
                       collapse="/"))
  repeat {
    x <- trimws(tolower(readline(prompt=msg)))
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

find_file_descend <- function(target, start=".", limit="/", error=TRUE) {
  root <- normalizePath(limit, mustWork=TRUE)
  start <- normalizePath(start, mustWork=TRUE)

  f <- function(path) {
    if (file.exists(file.path(path, target))) {
      return(path)
    }
    if (normalizePath(path, mustWork=TRUE) == root) {
      if (error) {
        stop(sprintf("Hit %s without finding %s", root, target))
      } else {
        return(NULL)
      }
    }
    Recall(file.path(path, ".."))
  }
  ret <- f(start)
  if (!(is.null(ret) && !error)) {
    ret <- normalizePath(ret, mustWork=TRUE)
  }
  ret
}

using_git <- function(path) {
  !is.null(find_file_descend(".git", path, error=FALSE))
}

Sys_getenv <- function(pos, fail=NULL) {
  for (i in pos) {
    x <- Sys.getenv(i, "")
    if (nzchar(x)) {
      return(x)
    }
  }
  fail
}

file_remove_if_exists <- function(...) {
  paths <- c(...)
  ok <- file.exists(paths)
  if (any(ok)) {
    file.remove(paths[ok])
  }
}

get_password_str <- function(verify, prompt) {
  pw <- getPass::getPass(prompt, TRUE)
  if (verify && nzchar(pw) &&
      !identical(getPass::getPass("Verify passphrase"), pw)) {
    stop("Passwords do not match", call.=FALSE)
  }
  pw
}
