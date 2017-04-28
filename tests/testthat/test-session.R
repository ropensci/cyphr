context("session")

test_that("object", {
  x <- runif(10)
  d <- session_encrypt(x)
  expect_is(d, "function")
  expect_identical(d(), x)

  ## Do not include sensitive information:
  e <- environment(d)
  expect_equal(ls(e, all.names = TRUE), "data") # in particular no 'key'
  expect_is(attr(e$data, "nonce", exact = TRUE), "raw")

  ## Environment chain includes nothing sensitive:
  expect_identical(parent.env(e), environment(session_encrypt))
})

test_that("raw", {
  y <- sodium::keygen()
  d <- session_encrypt(y)
  expect_is(d, "function")
  expect_identical(d(), y)

  ## Do not include sensitive information:
  e <- environment(d)
  expect_equal(ls(e, all.names = TRUE), "data") # in particular no 'key'
  expect_is(attr(e$data, "nonce", exact = TRUE), "raw")

  ## Environment chain includes nothing sensitive:
  expect_identical(parent.env(e), environment(session_encrypt))
})

test_that("classed raw objects", {
  y <- as.raw(1:10)
  class(y) <- "mything"
  d <- session_encrypt(y)
  expect_identical(d(), y)
})

test_that("refresh session key", {
  y <- sodium::keygen()
  d <- session_encrypt(y)
  session_key_refresh()
  expect_error(d(), "Failed to decrypt")
})
