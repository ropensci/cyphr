context("wrappers")

test_that("se", {
  on.exit(file_remove_if_exists("output.rds"))
  x <- config_symmetric(sodium::keygen())
  encrypt_(quote(saveRDS(iris, "output.rds")), x)
  expect_identical(decrypt_(quote(readRDS("output.rds")), x), iris)
  expect_error(readRDS("output.rds"), "unknown input format")
})

test_that("nse", {
  x <- config_symmetric(sodium::keygen())
  len <- length(dir(tempdir()))

  filename <- tempfile()
  on.exit(file_remove_if_exists(filename))

  encrypt(saveRDS(iris, filename), x)
  expect_true(file.exists(filename))
  ## Only one extra file in the tempdir; nothing else left.
  expect_equal(length(dir(tempdir())), len + 1L)
  expect_error(readRDS(filename), "unknown input format")
  expect_equal(decrypt(readRDS(filename), x), iris)
})

test_that("nse 2", {
  x <- config_symmetric(sodium::keygen())
  filename <- tempfile()
  on.exit(file_remove_if_exists(filename))

  encrypt(write.csv(iris, filename, row.names=FALSE), x)
  expect_true(file.exists(filename))

  expect_warning(readLines(filename), "embedded nul")

  expect_equal(decrypt(read.csv(filename), x), iris)
})
