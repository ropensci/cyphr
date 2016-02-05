##' Create a pair of public and private keys, possibly with password
##' protection.  If you're trying to do the data workflow thing, use
##' \code{\link{data_user_init}} instead, which wraps this but puts
##' the key in the place the rest of the functions there will look.
##'
##' The functions \code{read_public_key} and \code{read_private_key}
##' will read the public and private key stored at \code{path}.  If
##' the private key is password-protected then you will be prompted
##' for a password.
##'
##' The \code{change_password} function will change the password of an
##' existing key.  This works by encrypting the private key, so the
##' actual key remains the same, only the password to lock it changes.
##'
##' @title Create keypair
##'
##' @param path Path to the directory to store the key.
##'
##' @param password What do we do about passwords?  Options are
##'   \code{FALSE} for no password, \code{TRUE} for prompting for a
##'   password, or a string value for a password (which will end up in
##'   things like your history so be careful).
##'
##' @param quiet Suppress printing of informative messages.
##'
##' @param name Leave this be for now.
##' @export
create_keypair <- function(path, password, quiet=FALSE, name="id_encryptr") {
  path_pub <- filename_pub(path)
  if (!file.exists(path_pub)) {
    if (!quiet) {
      message("Creating public key in ", path_pub)
    }

    dir.create(path, FALSE, TRUE)
    path_key <- filename_key(path, name)
    path_pub <- filename_pub(path, name)

    pair <- generate_keypair(password)
    write_private_key(pair$key, path)

    ## Collect metadata:
    info <- Sys.info()
    dat <- list(user=info[["user"]],
                host=info[["nodename"]],
                date=as.character(Sys.time()),
                pub=bin2str(pair$pub))
    write.dcf(dat, path_pub, width=500)
  }
  invisible(path_pub)
}

##' @export
##' @rdname create_keypair
change_password <- function(path, password, quiet=FALSE) {
  path <- data_path_user(path)
  name <- "id_encryptr"
  key <- .read_private_key(path, NULL, "Enter current passphrase")
  pw <- create_password(password)
  if (!is.null(pw)) {
    key <- pack_data(sodium::data_encrypt(key, pw))
  }
  write_private_key(key, path)
  invisible(TRUE)
}

##' @export
##' @rdname create_keypair
read_private_key <- function(path) {
  .read_private_key(path, NULL, "Enter passphrase")
}

##' @export
##' @rdname create_keypair
read_public_key <- function(path) {
  if (is_directory(path)) {
    filename <- filename_pub(path)
  } else {
    filename <- path
  }
  if (!file.exists(filename)) {
    stop("Public key not found at ", path)
  }
  dat <- as.list(read.dcf(filename)[1, ])
  dat$pub <- sodium::hex2bin(dat$pub)
  dat$hash <- data_hash(filename)
  dat$filename <- filename
  class(dat) <- "key"
  dat
}

##' @export
print.key <- function(x, ...) {
  cat(as.character(x), "\n", sep="")
}
##' @export
as.character.key <- function(x, ...) {
  v <- c("user", "host", "date", "pub")
  x$pub <- bin2str(x$pub)
  x$hash <- bin2str(x$hash)
  sprintf("%s:\n%s", bin2str(x$hash),
          paste(sprintf("  %4s: %s", v, unlist(x[v])), collapse="\n"))
}

## This does the *actual* generation.
generate_keypair <- function(password) {
  key <- sodium::keygen()
  pub <- sodium::pubkey(key)
  pw <- create_password(password)
  if (!is.null(pw)) {
    key <- pack_data(sodium::data_encrypt(key, pw))
  }
  list(key=key, pub=pub)
}

filename_key <- function(path, name="id_encryptr") {
  paste0(file.path(path, name), ".key")
}
filename_pub <- function(path, name="id_encryptr") {
  paste0(file.path(path, name), ".pub")
}

## NOTE: this might be better with a toolkit package, but that seems
## unlikely fo a very heavy dependency tail (installing the gtk things
## is horrible).
##
## NOTE: focus issues on windows and OSX:
##   - on windows the focus does not follow to the dialog
##   - on OSX the focus does not return to R (in terminal or Rgui)
##
## Another option is to use shiny; that seems like a bit of a hassle
## but might work.
password_tcltk <- function(prompt="Enter passphrase") {
  loadNamespace("tcltk")
  ok <- FALSE

  wnd <- tcltk::tktoplevel()
  tcltk::tktitle(wnd) <- prompt
  pass_var <- tcltk::tclVar("")

  submit <- function() {
    tcltk::tkdestroy(wnd)
    ok <<- TRUE
  }
  cancel <- function() {
    tcltk::tkdestroy(wnd)
  }
  pass_box <- tcltk::tkentry(wnd, textvariable=pass_var, show="*")
  tcltk::tkgrid(tcltk::tklabel(wnd, text=prompt),
                pass_box)
  tcltk::tkgrid(tcltk::tkbutton(wnd, text="OK", command=submit),
                tcltk::tkbutton(wnd, text="Cancel", command=cancel))
  tcltk::tkbind(pass_box, "<Return>", submit)
  tcltk::tkbind(pass_box, "<Escape>", cancel)
  tcltk::tkfocus(pass_box)
  ## Various attempts at getting focus that don't work on Windows:
  ##   tcltk::tkfocus(wnd)
  ##   tcltk::tkraise(wnd)
  ##   tcltk::tcl("wm", "attributes", wnd, topmost=TRUE)
  ## we do get default focus on Linux / OSX though it takes ages to
  ## start X on OSX.
  tcltk::tkwait.window(wnd)

  if (!ok) {
    stop("Did not recieve password")
  }
  pw <- tcltk::tclvalue(pass_var)
  invisible(pw)
}

password_unix <- function(prompt="Enter passphrase") {
  ## Emacs/ess can *almost* pull this off; the password bit gets
  ## triggered ok but afterwards it will entirely print.
  if (!grepl(":\\s*", prompt)) {
    paste0(prompt, ": ")
  }
  cat(prompt)
  stty <- Sys.which("stty")
  ok <- system2(stty, "-echo")
  if (ok != 0) {
    stop("Error using stty")
  }
  on.exit({system2(stty, "echo"); cat("\n")})
  invisible(readline())
}

## Switch between text and graphical mode.  Detection based on Gabor's
## crayon package:
is_terminal <- function() {
  (getOption("encryptr.password.tcltk", FALSE) != TRUE) &&
    isatty(stdout()) &&
    (.Platform$OS.type != "windows") &&
    (Sys.getenv("TERM") != "dumb") &&
    (Sys.getenv("EMACS") == "") &&
    (Sys.which("stty") != "")
}

get_password <- function(verify, min_length=0, prompt="Enter passphrase") {
  password <- if (is_terminal()) password_unix else password_tcltk
  pw <- password(prompt)
  if (nchar(pw) < min_length) {
    stop(sprintf("At least %d characters required", min_length))
  }
  if (verify && nchar(pw) > 0L &&
      !identical(password("Verify passphrase"), pw)) {
    stop("Passwords do not match")
  }
  invisible(if (nchar(pw) == 0) NULL else sodium::scrypt(charToRaw(pw)))
}

get_password_str <- function(verify, min_length=0, prompt="Enter passphrase") {
  password <- if (is_terminal()) password_unix else password_tcltk
  pw <- password(prompt)
  if (nchar(pw) < min_length) {
    stop(sprintf("At least %d characters required", min_length))
  }
  if (verify && nchar(pw) > 0L &&
      !identical(password("Verify passphrase"), pw)) {
    stop("Passwords do not match")
  }
  pw
}

write_private_key <- function(key, path, name="id_encryptr") {
  path_key <- filename_key(path, name)
  writeBin(key, path_key)
  ## TODO: Not sure if this is always supported, e.g. on Windows
  Sys.chmod(path_key, "600")
}

## Expose a few options for internal use here:
.read_private_key <- function(path, password, prompt) {
  filename <- filename_key(path)
  if (!file.exists(filename)) {
    stop("Key not found at ", path)
  }
  dat <- read_binary(filename)
  if (length(dat) == 32L) {
    dat
  } else {
    if (is.null(password)) {
      if (!interactive()) {
        ## This is only for testing; could enforce that I guess.
        password <- getOption("encryptr.password", NULL)
        if (is.null(password)) {
          stop("Password required but running in non-interactive mode")
        }
        password <- sodium::scrypt(charToRaw(password))
      } else {
        ## min_length of 1 OK because empty string passwords not allowed.
        password <- get_password(FALSE, 1, prompt=prompt)
      }
    } else if (is.character(password)) {
      password <- sodium::scrypt(charToRaw(password))
    }
    tryCatch(sodium::data_decrypt(unpack_data(dat), password),
             error=function(e) stop("Invalid password", call.=FALSE))
  }
}

create_password <- function(password) {
  if (isTRUE(password)) {
    pw <- get_password(TRUE, prompt="Enter new passphrase")
  } else if (is.character(password)) {
    ## TODO: consider censoring history by one line here.
    pw <- sodium::scrypt(charToRaw(password))
  } else if (identical(password, FALSE)) {
    pw <- NULL
  } else {
    stop("Invalid value for password")
  }
  pw
}
