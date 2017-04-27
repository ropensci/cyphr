##' Wrapper around \code{ssh-keygen}(1).  In general this should not
##' be used (generate keys yourself with \code{ssh-keygen} at the
##' command line.  However this is useful for testing and
##' demonstration so I have included it to make that easier.  Once a
##' keypair has been generated it can be used with
##' \code{\link{keypair_openssl}}.
##'
##' @title Wrapper around ssh-keygen
##' @param path A directory in which to create a keypair.  If the path
##'   does not exist it will be created.
##' @param password The password for the key.  The default will prompt
##'   interactively (but without echoing the password).  Other valid
##'   options are \code{FALSE} (no password) or a string.
##' @return The \code{path}, invisibly.  This is useful in the case
##'   where \code{path} is \code{\link{tempfile}()}.
##' @export
##' @examples
##' \dontrun{
##' # Generate a new key in a temporary directory:
##' path <- ssh_keygen(password = FALSE)
##' dir(path) # will contain id_rsa and id_rsa.pub
##'
##' # This key can now be used via config_openssl:
##' cfg <- config_openssl(path)
##' secret <- encrypt_string("hello", NULL, cfg)
##' decrypt_string(secret, cfg)
##' }
ssh_keygen <- function(path = tempfile(), password = TRUE) {
  ssh_keygen <- Sys_which("ssh-keygen")
  if (file.exists(path) && !is_directory(path)) {
    stop("path exists but is not a directory")
  }
  dir.create(path, FALSE, TRUE)
  dest_key <- file.path(path, "id_rsa")
  dest_pub <- file.path(path, "id_rsa.pub")
  if (file.exists(dest_key)) {
    stop("private key ", dest_key, " exists already -- not overwriting")
  }
  if (file.exists(dest_pub)) {
    stop("public key ", dest_pub, " exists already -- not overwriting")
  }

  if (isTRUE(password)) {
    pw <- get_password_str(TRUE, "Enter passphrase: ")
  } else if (identical(password, FALSE)) {
    pw <- "''"
  } else if (is.character(password)) {
    pw <- if (nzchar(password)) password else "''"
  } else {
    stop("Invalid input for password")
  }

  code <- system2(ssh_keygen, c("-q", "-N", pw, "-f", dest_key))
  if (code != 0L) {
    stop("Error running ssh-keygen")
  }

  invisible(path)
}
