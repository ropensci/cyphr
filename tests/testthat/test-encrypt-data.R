context("encrypt_data")

test_that("encrypt_data", {
  pair <- keypair_openssl("pair1", "pair1")
  r <- openssl::rand_bytes(20)

  v <- encrypt_data(r, pair, NULL)
  expect_is(v, "raw")
  expect_identical(decrypt_data(v, pair, NULL), r)
})

test_that("encrypt_object", {
  pair <- keypair_openssl("pair1", "pair1")
  r <- list(runif(10), sample(20))

  v <- encrypt_object(r, pair, NULL)
  expect_is(v, "raw")
  expect_identical(decrypt_object(v, pair), r)
})

test_that("encrypt_string", {
  pair <- keypair_openssl("pair1", "pair1")
  r <- paste(sample(letters), collapse = "")

  v <- encrypt_string(r, pair)
  expect_is(v, "raw")
  expect_identical(decrypt_string(v, pair), r)
})

test_that("encrypt_file", {
  pair <- keypair_openssl("pair1", "pair1")
  path1 <- tempfile()
  path2 <- tempfile()
  path3 <- tempfile()
  on.exit(suppressWarnings(file.remove(path1, path2, path3)))

  write.csv(mtcars, path1)
  encrypt_file(path1, pair, path2)
  expect_true(file.exists(path2))
  expect_false(unname(tools::md5sum(path1)) == unname(tools::md5sum(path2)))

  decrypt_file(path2, pair, path3)
  expect_true(file.exists(path3))
  expect_identical(unname(tools::md5sum(path1)),
                   unname(tools::md5sum(path3)))
})

test_that("input validation", {
  key <- key_sodium(sodium::keygen())
  expect_error(encrypt_data(iris, key),
               "Expected a raw vector")
  expect_error(encrypt_string(raw(10), key),
               "must be a scalar character")
  expect_error(encrypt_string(letters, key),
               "must be a scalar character")
})

test_that("decrypt_data from file", {
  key <- key_sodium(sodium::keygen())
  path <- tempfile()
  r <- sodium::random(20)
  encrypt_data(r, key, path)

  expect_identical(decrypt_data(path, key), r)
  expect_error(decrypt_data(tempfile(), key),
               "must be a file that exists")
})
