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
