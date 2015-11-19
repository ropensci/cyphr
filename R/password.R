## TODO: Handle:
##   - empty string
##   - closed window (which gives an empty string but might be
##     monitorable with an event).
##
## TODO: See if any other gui toolkit packages offer something less ugly.
password_tcltk <- function(prompt="Enter passphrase", title=prompt) {
  loadNamespace("tcltk")
  wnd <- tcltk::tktoplevel()
  tcltk::tktitle(wnd) <- title
  pass_var <- tcltk::tclVar("")
  command <- function() tcltk::tkdestroy(wnd)
  tcltk::tkgrid(tcltk::tklabel(wnd, text=prompt))
  tcltk::tkgrid(pass_box <- tcltk::tkentry(wnd, textvariable=pass_var, show="*"))
  tcltk::tkbind(pass_box, "<Return>", command)
  tcltk::tkgrid(tcltk::tkbutton(wnd, text="OK", command=command))
  tcltk::tkfocus(pass_box)
  ## Various attempts at getting focus that don't work on Windows:
  ##   tcltk::tkfocus(wnd)
  ##   tcltk::tkraise(wnd)
  ##   tcltk::tcl("wm", "attributes", wnd, topmost=TRUE)
  ## we do get default focus on Linux / OSX though it takes ages to
  ## start X on OSX.
  tcltk::tkwait.window(wnd)
  browser()
  invisible(sodium::scrypt(charToRaw(tcltk::tclvalue(pass_var))))
}

get_password <- function(verify) {
  pw <- password_tcltk("Enter passphrase")
  if (verify && !identical(password_tcltk("Verify passphrase"), pw)) {
    stop("Passwords do not match")
  }
  invisible(pw)
}
