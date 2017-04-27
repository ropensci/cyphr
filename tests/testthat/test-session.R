context("session")

test_that("object", {
  x <- runif(10)
  d <- session_encrypt(x)
  expect_is(d, "function")
  expect_identical(d(), x)
})

test_that("raw", {
  y <- sodium::keygen()
  d <- session_encrypt(y)
  expect_is(d, "function")
  expect_identical(d(), y)
})

test_that("force object", {
  y <- sodium::keygen()
  d1 <- session_encrypt(y)
  d2 <- session_encrypt(y, TRUE)
  expect_lt(length(environment(d1)$data),
            length(environment(d2)$data))
})

test_that("refresh session key", {
  y <- sodium::keygen()
  d <- session_encrypt(y)
  session_key_refresh()
  expect_error(d(), "Failed to decrypt")
})
