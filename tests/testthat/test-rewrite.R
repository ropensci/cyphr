context("rewrite")

## This is just a random set of what would want to be a significantly
## more beefed up set given how evil rewrite is.
test_that("command rewriting", {
  res <- rewrite(quote(readRDS("myfile.rds")), filename="newname")
  expect_equal(res$filename, "myfile.rds")
  expect_equal(res$expr, quote(readRDS(file="newname")))
  expect_equal(res$tmp, "newname")

  ## NOTE: This does change argument order...
  res <- rewrite(quote(readRDS(NULL, file="myfile.rds")), filename="newname")
  expect_equal(res$filename, "myfile.rds")
  expect_equal(res$expr, quote(readRDS(file="newname", refhook=NULL)))

  ## with dots:
  res <- rewrite(quote(read.csv("myfile.csv", stringsAsFactors=FALSE)),
                 filename="newname")
  expect_equal(res$filename, "myfile.csv")
  expect_equal(res$expr,
               quote(read.csv(file="newname", stringsAsFactors=FALSE)))

  res <- rewrite(quote(write.csv(x, "myfile.csv")), filename="other.csv")
  expect_equal(res$filename, "myfile.csv")
  expect_equal(res$tmp, "other.csv")
  expect_equal(res$expr, quote(write.csv(x=x, file="other.csv")))

  expect_error(rewrite(quote(readRDS("myfile")), file_arg="foo"),
               "Cannot inferr file argument")
  expect_error(rewrite(quote(unknown("myfile"))),
               "was not found")
  expect_error(rewrite(quote(plot("myfile"))),
               "not found in database")
})
