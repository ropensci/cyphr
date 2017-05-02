context("assertions")

test_that("assert_is", {
  expect_error(assert_is(NULL, "function"),
               "must be a function")
  expect_silent(assert_is(sin, "function"))
})

test_that("assert_raw", {
  expect_error(assert_raw(1), "must be raw")
  expect_silent(assert_raw(raw(1)))
})
