## TODO: Handle:
##   - empty string
##   - closed window (which gives an empty string but might be
##     monitorable with an event).
##
## TODO: See if any other gui toolkit packages offer something less ugly.
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

get_password <- function(verify, min_length=0) {
  pw <- password_tcltk("Enter passphrase", min_length=min_length)
  if (verify && nchar(pw) > 0L &&
      !identical(password_tcltk("Verify passphrase"), pw)) {
    stop("Passwords do not match")
  }
  invisible(if (nchar(pw) > 0) pw else NULL)
}

keypair <- function(password) {
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

## NOTE: this does not support passing in passwords at all; I don't
## think that's a bad thing though.
load_private_key <- function(path) {
  dat <- read_binary(path)
  if (length(dat) == 32L) {
    dat
  } else {
    pw <- sodium::scrypt(charToRaw(get_password(FALSE)))
    tryCatch(sodium::data_decrypt(split_nonce(dat), pw),
             error=function(e) stop("Invalid password", call.=FALSE))
  }
}
