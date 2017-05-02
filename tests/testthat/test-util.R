context("util")

test_that("Sys_which", {
  expect_error(Sys_which("nonexistantbinary"), "Can not find")
})

test_that("get_password_str", {
  testthat::with_mock(
    `cyphr:::get_pass` = function(prompt)
      if (grepl("Verify", prompt)) "a" else "b",
    expect_error(get_password_str(TRUE, "password"),
                 "Passwords do not match"),
    expect_equal(get_password_str(FALSE, "password"),
                 "b"))

  testthat::with_mock(
    `cyphr:::get_pass` = function(prompt) "a",
    expect_equal(get_password_str(TRUE, "password"), "a"),
    expect_equal(get_password_str(FALSE, "password"), "a"))
})
