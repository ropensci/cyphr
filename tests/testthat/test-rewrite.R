context("rewrite")

## This is just a random set of what would want to be a significantly
## more beefed up set given how evil rewrite is.
test_that("command rewriting", {
  res <- rewrite(quote(readRDS("myfile.rds")), filename = "newname")
  expect_equal(res$filename, "myfile.rds")
  expect_equal(res$expr, quote(readRDS(file = "newname")))
  expect_equal(res$tmp, "newname")

  ## NOTE: This does change argument order...
  res <- rewrite(quote(readRDS(NULL, file = "myfile.rds")),
                 filename = "newname")
  expect_equal(res$filename, "myfile.rds")
  expect_equal(res$expr, quote(readRDS(file = "newname", refhook = NULL)))

  ## with dots:
  res <- rewrite(quote(read.csv("myfile.csv", stringsAsFactors = FALSE)),
                 filename = "newname")
  expect_equal(res$filename, "myfile.csv")
  expect_equal(res$expr,
               quote(read.csv(file = "newname", stringsAsFactors = FALSE)))

  res <- rewrite(quote(write.csv(x, "myfile.csv")), filename = "other.csv")
  expect_equal(res$filename, "myfile.csv")
  expect_equal(res$tmp, "other.csv")
  expect_equal(res$expr, quote(write.csv(x = x, file = "other.csv")))

  expect_error(rewrite(quote(readRDS("myfile")), file_arg = "foo"),
               "Cannot infer file argument")
  expect_error(rewrite(quote(unknown("myfile"))))
  expect_error(rewrite(quote(plot("myfile"))),
               "Rewrite rule for graphics::plot not found", fixed = TRUE)
})

test_that("filename default argument", {
  ## Filename from default:
  f <- function(x, filename = "foo") {
  }
  res <- rewrite(quote(f(1)), "filename")
  expect_equal(res$filename, "foo") # captured default arg
  expect_equal(res$expr[["filename"]], res$tmp) # rewrote expression

  res <- rewrite(quote(f(1, "bar")), "filename")
  expect_equal(res$filename, "bar") # user-supplied arg
})

test_that("redefined base functions", {
  f <- readRDS
  res <- rewrite(quote(f("myfile.rds")))
  expect_equal(res$filename, "myfile.rds")
  expect_equal(res$expr$file, res$tmp)
})

test_that("corner case", {
  expect_error(rewrite(quote(foo)),
               "Expected call")
})

test_that("namespaced functions", {
  res <- rewrite(quote(base::readRDS("myfile.rds")), filename = "newname")
  expect_equal(res$filename, "myfile.rds")
  expect_equal(res$expr, quote(base::readRDS(file = "newname")))
  expect_equal(res$tmp, "newname")
})

## This is not ideal and there may be other cases where this fails
## badly.
test_that("invalid input", {
  expect_error(rewrite(quote(1(foo))), "Confused")
  expect_error(rewrite(quote(factory()(foo))), "Invalid function call for name")
})

test_that("register", {
  on.exit(rewrite_reset())

  ## Simple case:
  rewrite_register("foo", "bar1", "baz")
  expect_equal(db[["foo::bar1"]],
               list(name = "bar1", package = "foo", arg = "baz", fn = NULL))

  ## Clash:
  expect_silent(rewrite_register("foo", "bar1", "baz"))
  expect_error(rewrite_register("foo", "bar1", "baz2"),
               "An entry already exists for foo::bar1")

  ## Other function:
  rewrite_register("foo", "bar2", "baz", c("a", "b"))
  expect_equal(db[["foo::bar2"]],
               list(name = "bar2", package = "foo", arg = "baz",
                    fn = c("a", "b")))

  ## Invalid package:
  expect_error(rewrite_register(NA, "bar2", "baz"),
               "package must be a non-NA scalar character")
  expect_error(rewrite_register("foo", "bar2", "baz", "a"),
               "fn must be a character vector of length 2")
})
