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

test_that("prompt_confirm", {
  ## testthat::skip_if_not_installed("mockr")
  testthat::with_mock(`cyphr:::read_line` = function(...) "n",
                      expect_equal(prompt_confirm(), FALSE))
  testthat::with_mock(`cyphr:::read_line` = function(...) "y",
                      expect_equal(prompt_confirm(), TRUE))
  testthat::with_mock(`cyphr:::read_line` = function(...) "",
                      expect_equal(prompt_confirm(), FALSE))

  first <- TRUE
  res <- testthat::with_mock(
    `cyphr:::read_line` = function(...) {
      if (first) {
        first <<- FALSE
        "x"
      } else {
        "y"
      }
    },
    evaluate_promise(prompt_confirm()))
  expect_equal(res$result, TRUE)
  expect_match(res$output, "Invalid choice")
})

test_that("Descend failure", {
  path <- tempfile()
  dir.create(path)
  on.exit(unlink(path, recursive = TRUE))
  expect_null(find_file_descend(".cyphr_foobar", tempdir(), path))
  expect_null(find_file_descend(".cyphr_foobar", "/", path))
  expect_null(find_file_descend(".cyphr_foobar", "/", "/"))
})


test_that("is_directory", {
  path <- tempfile()
  expect_false(is_directory(path))
  file.create(path)
  expect_false(is_directory(path))
  unlink(path)
  dir.create(path)
  expect_true(is_directory(path))
})
