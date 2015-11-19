is_directory <- function(x) {
  file.exists(x) && file.info(x, FALSE)[["isdir"]]
}

bin2str <- function(x, sep="::") {
  paste(as.character(x), collapse=sep)
}
str2bin <- function(x) {
  sodium::hex2bin(x)
}
