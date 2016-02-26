## NOTE: Drew Schmitt (wrathmatics) is working on a crossplatform
## password-getter that works nicely with Rstudio etc.  Use that once
## it's available (it's currently on github only but we could probably
## get that via drat?)

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
    prompt <- paste0(prompt, ": ")
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
    stop("Passwords do not match", call.=FALSE)
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
    stop("Passwords do not match", call.=FALSE)
  }
  pw
}
