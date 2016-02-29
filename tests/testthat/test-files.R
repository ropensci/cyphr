context("files")

test_that("public", {
  key <- sodium::keygen()
  pub <- sodium::pubkey(key)

  x <- config_sodium_public(pub, key)

  path1 <- tempfile()
  path2 <- tempfile()
  path3 <- tempfile()
  on.exit(file.remove(path1, path2, path3))
  saveRDS(iris, path1)

  encrypt_file(path1, path2, x)
  expect_true(file.exists(path2))
  expect_error(readRDS(path2), "unknown input format")

  decrypt_file(path2, path3, x)
  expect_true(file.exists(path3))
  expect_identical(readRDS(path3), readRDS(path1))
  expect_identical(read_binary(path3), read_binary(path1))
})

test_that("symmetric encryption", {
  x <- config_sodium_symmetric(sodium::keygen())

  path1 <- tempfile()
  path2 <- tempfile()
  path3 <- tempfile()
  on.exit(file.remove(path1, path2, path3))
  saveRDS(iris, path1)

  encrypt_file(path1, path2, x)
  expect_true(file.exists(path2))
  expect_error(readRDS(path2), "unknown input format")

  decrypt_file(path2, path3, x)
  expect_true(file.exists(path3))
  expect_identical(readRDS(path3), readRDS(path1))
  expect_identical(read_binary(path3), read_binary(path1))
})

test_that("authenticated", {
  ## User1:
  key1 <- sodium::keygen()
  pub1 <- sodium::pubkey(key1)
  ## User2:
  key2 <- sodium::keygen()
  pub2 <- sodium::pubkey(key2)

  x1 <- config_sodium_authenticated(pub2, key1)
  x2 <- config_sodium_authenticated(pub1, key2)

  path1 <- tempfile()
  path2 <- tempfile()
  path3 <- tempfile()
  on.exit(file.remove(path1, path2, path3))
  saveRDS(iris, path1)

  encrypt_file(path1, path2, x1)
  expect_true(file.exists(path2))
  expect_error(readRDS(path2), "unknown input format")

  decrypt_file(path2, path3, x2)
  expect_true(file.exists(path3))
  expect_identical(readRDS(path3), readRDS(path1))
  expect_identical(read_binary(path3), read_binary(path1))
})
