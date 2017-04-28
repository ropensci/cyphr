context("openssl")

test_that("keygen", {
  path <- tempfile()
  res <- ssh_keygen(path, "secret")
  expect_equal(res, path)
  expect_true(is_directory(path))
  expect_true(file.exists(file.path(path, "id_rsa")))
  expect_true(file.exists(file.path(path, "id_rsa.pub")))
})

test_that("existing, but not directory", {
  path <- tempfile()
  writeLines("", path)
  on.exit(file.remove(path))
  expect_error(ssh_keygen(path), "path exists but is not a directory")
})

test_that("existing, but not directory", {
  path <- tempfile()
  dir.create(path)
  writeLines("", file.path(path, "id_rsa.pub"))
  expect_error(ssh_keygen(path), "public.*exists already -- not overwriting")
  writeLines("", file.path(path, "id_rsa"))
  expect_error(ssh_keygen(path), "private.*exists already -- not overwriting")
})

test_that("load; no password", {
  d <- openssl_load_key("pair1")
  expect_is(d, "key")
})

test_that("load; with password", {
  pw <- "secret"
  path <- ssh_keygen(password = pw)
  d <- openssl_load_key(path, pw)
  expect_is(d, "key")

  expect_error(openssl_load_key(path, "wrong password"),
               "bad decrypt")
})

test_that("pair", {
  pair <- keypair_openssl("pair1", "pair1")
  expect_is(pair, "cyphr_keypair")
  expect_is(pair, "cyphr_key")
  expect_equal(pair$type, "openssl")
  expect_is(pair$pub, "pubkey")
  expect_is(pair$key, "function")
  expect_is(pair$key(), "key")
  expect_is(pair$encrypt, "function")
  expect_is(pair$decrypt, "function")

  r <- openssl::rand_bytes(20)
  v <- pair$encrypt(r)
  expect_is(v, "list")
  expect_identical(pair$decrypt(v), r)
})

test_that("pair - communicate", {
  pair_a <- keypair_openssl("pair2", "pair1")
  pair_b <- keypair_openssl("pair1", "pair2")

  r <- openssl::rand_bytes(20)
  v <- pair_a$encrypt(r)
  expect_identical(pair_b$decrypt(v), r)
  expect_identical(pair_a$decrypt(pair_b$encrypt(r)), r)

  session_key_refresh()
  expect_error(pair_b$decrypt(v), "Failed to decrypt")
})

test_that("asymmetric", {
  k <- openssl::aes_keygen()
  key <- key_openssl(k)
  expect_is(key, "cyphr_key")
  expect_equal(key$type, "openssl")
  expect_is(key$key, "function")
  expect_identical(key$key(), k)
  expect_is(key$encrypt, "function")
  expect_is(key$decrypt, "function")

  r <- openssl::rand_bytes(20)
  v <- key$encrypt(r)
  expect_is(attr(v, "iv", exact = TRUE), "raw")
  expect_identical(key$decrypt(v), r)
})
