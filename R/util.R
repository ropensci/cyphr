get_password_str <- function(verify, prompt) {
  pw <- getPass::getPass(prompt, TRUE)
  if (verify && nzchar(pw) &&
      !identical(getPass::getPass("Verify passphrase"), pw)) {
    stop("Passwords do not match", call.=FALSE)
  }
  pw
}

is_directory <- function(x) {
  file.exists(x) && file.info(x, FALSE)[["isdir"]]
}

Sys_which <- function(name) {
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
