for (i in 1:2) {
  dest <- paste0("pair", i)
  if (!file.exists(dest)) {
    ssh_keygen(dest, password = FALSE)
  }
}
