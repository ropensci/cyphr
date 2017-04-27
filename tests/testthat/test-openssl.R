context("openssl")

test_that("keygen", {
  path <- tempfile()
  res <- ssh_keygen(path, "secret")
  expect_equal(res, path)
  expect_true(is_directory, path)
  expect_true(file.exists(file.path(path, "id_rsa")))
  expect_true(file.exists(file.path(path, "id_rsa.pub")))
})

test_that("existing, but not directory", {
  path <- tempfile()
  writeLines("", path)
  on.exit(file.remove(path))
  expect_error(ssh_keygen(path), "path exists but is not a directory")
})

test_that("existing, but not directory", {
  path <- tempfile()
  dir.create(path)
  writeLines("", file.path(path, "id_rsa.pub"))
  expect_error(ssh_keygen(path), "public.*exists already -- not overwriting")
  writeLines("", file.path(path, "id_rsa"))
  expect_error(ssh_keygen(path), "private.*exists already -- not overwriting")
})

test_that("load; no password", {
  path <- ssh_keygen(password = FALSE)
  d <- identity_openssl(path)
  expect_is(d(), "key")
})

test_that("load; with password", {
  pw <- "secret"
  path <- ssh_keygen(password = pw)
  d <- identity_openssl(path, pw)
  expect_is(d(), "key")

  expect_error(d <- identity_openssl(path, "wrong password"),
               "bad decrypt")
})
