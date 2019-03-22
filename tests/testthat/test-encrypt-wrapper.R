context("encrypt() wrappers")

test_that("se", {
  path <- tempfile()
  on.exit(file_remove_if_exists(path))
  x <- key_sodium(sodium::keygen())
  encrypt_(quote(saveRDS(iris, path)), x)
  expect_identical(decrypt_(quote(readRDS(path)), x), iris)
  ## Matching the exact message here is error-prone
  expect_error(readRDS(path))
})

test_that("nse", {
  x <- key_sodium(sodium::keygen())
  len <- length(dir(tempdir()))

  filename <- tempfile()
  on.exit(file_remove_if_exists(filename))

  encrypt(saveRDS(iris, filename), x)
  expect_true(file.exists(filename))
  ## Only one extra file in the tempdir; nothing else left.
  expect_equal(length(dir(tempdir())), len + 1L)
  expect_error(readRDS(filename))
  expect_equal(decrypt(readRDS(filename), x), iris)
})

test_that("nse 2", {
  x <- key_sodium(sodium::keygen())
  filename <- tempfile()
  on.exit(file_remove_if_exists(filename))

  encrypt(write.csv(iris, filename, row.names = FALSE), x)
  expect_true(file.exists(filename))

  expect_equal(decrypt(read.csv(filename), x), iris)
})

test_that("visibility", {
  ## Also is a test for custom functions :-\
  f <- function(x, filename = tempfile(), visible = FALSE) {
    saveRDS(x, filename)
    if (visible) filename else invisible(filename)
  }

  x <- key_sodium(sodium::keygen())
  expect_error(encrypt(f(iris), x), "Rewrite rule for f not found")
  res <- withVisible(encrypt(f(iris), x, file_arg = "filename"))
  expect_false(res$visible)

  rewrite_register("", "f", "filename")
  res <- withVisible(encrypt(f(iris), x))
  expect_false(res$visible)

  res <- withVisible(encrypt(f(iris, visible = TRUE), x))
  expect_true(res$visible)
})

test_that("non-file arguments", {
  x <- key_sodium(sodium::keygen())
  f <- tempfile()
  on.exit(file.remove(f))
  con <- file(f, "wb")
  ## Encryption works:
  with_connection(con, encrypt(saveRDS(iris, con), x))

  ## Validiate:
  expect_identical(decrypt(readRDS(f), x), iris)

  con2 <- file(f, "rb")
  expect_identical(with_connection(con, decrypt(readRDS(con2), x)), iris)
})
