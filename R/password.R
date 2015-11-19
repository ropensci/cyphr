##' Create a pair of public and private keys, possibly with password
##' protection.  If you're trying to do the data workflow thing, use
##' \code{\link{data_user_init}} instead, please.
##'
##' The functions \code{read_public_key} and \code{read_private_key}
##' will read the public and private key stored at \code{path}.  If
##' the private key is password-protected then you will be prompted
##' for a password.
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

    writeBin(pair$key, path_key)
    ## TODO: Not sure if this is always supported, e.g. on Windows
    Sys.chmod(path_key, "600")

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
read_private_key <- function(path) {
  dat <- read_binary(filename_key(path))
  if (length(dat) == 32L) {
    dat
  } else {
    pw <- sodium::scrypt(charToRaw(get_password(FALSE)))
    tryCatch(sodium::data_decrypt(split_nonce(dat), pw),
             error=function(e) stop("Invalid password", call.=FALSE))
  }
}

##' @export
##' @rdname create_keypair
read_public_key <- function(path) {
  if (is_directory(path)) {
    filename <- filename_pub(path)
  } else if (file.exists(path)) {
    filename <- path
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

  if (isTRUE(password)) {
    pw <- get_password(TRUE)
  } else if (is.character(password)) {
    ## TODO: consider censoring history by one line here.
    pw <- password
  } else if (identical(password, FALSE)) {
    pw <- NULL
  } else {
    stop("Invalid value for password")
  }

  if (!is.null(pw)) {
    key <- add_nonce(sodium::data_encrypt(key, sodium::scrypt(charToRaw(pw))))
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
password_tcltk <- function(prompt="Enter passphrase", title=prompt,
                           min_length=0) {
  loadNamespace("tcltk")
  ok <- FALSE

  wnd <- tcltk::tktoplevel()
  tcltk::tktitle(wnd) <- title
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
  if (nchar(pw) < min_length) {
    stop(sprintf("At least %d characters required", min_length))
  }
  invisible(pw)
}

password_unix <- function(prompt="Enter passphrase", min_length=0) {
  ## Emacs/ess can *almost* pull this off; the password bit gets
  ## triggered ok but afterwards it will entirely print.
  cat(paste0(prompt, ": "))
  pw <- system('stty -echo && read ff && stty echo && echo $ff && ff=""',
               intern=TRUE)
  cat('\n')
  invisible(pw)
}

## Switch between text and graphical mode.  Detection based on Gabor's
## crayon package:
is_terminal <- function() {
  (getOption("encryptr.password.tcltk", FALSE) != TRUE) &&
    isatty(stdout()) &&
    (.Platform$OS.type != "windows") &&
    (Sys.getenv("TERM") != "dumb") &&
    (Sys.getenv("EMACS") == "")
}

get_password <- function(verify, min_length=0) {
  password <- if (is_terminal()) password_unix else password_tcltk
  pw <- password("Enter passphrase", min_length=min_length)
  if (verify && nchar(pw) > 0L &&
      !identical(password("Verify passphrase"), pw)) {
    stop("Passwords do not match")
  }
  invisible(if (nchar(pw) > 0) pw else NULL)
}
