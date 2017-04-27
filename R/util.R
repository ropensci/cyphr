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
