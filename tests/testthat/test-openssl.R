context("openssl")

test_that("load; no password", {
  d <- openssl_load_key("pair1")
  expect_is(d, "key")
})

test_that("load; with password", {
  pw <- "secret"
  path <- ssh_keygen(password = pw)
  d <- openssl_load_key(path, pw)
  expect_is(d, "key")

  expect_error(openssl_load_key(path, "wrong password"))

  testthat::with_mock(
    `cyphr:::get_password_str` = function(...) pw,
    expect_is(openssl_load_key(path), "key"))
  testthat::with_mock(
    `cyphr:::get_password_str` = function(...) "wrong",
    expect_error(openssl_load_key(path)))
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
  expect_is(v, "raw")
  expect_gt(length(v), length(r))
  expect_identical(pair$decrypt(v), r)
})

test_that("pair - non envelope", {
  pair <- keypair_openssl("pair1", "pair1", envelope = FALSE)
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
  expect_gt(length(v), length(r))
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

test_that("symmetric", {
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
  expect_identical(key$decrypt(v), r)
})

test_that("symmetric", {
  k <- openssl::aes_keygen()
  r <- openssl::rand_bytes(20)
  for (mode in c("cbc", "ctr", "gcm")) {
    key <- key_openssl(k, mode)
    if (!(mode == "gcm" && identical(Sys.getenv("TRAVIS"), "true"))) {
      expect_identical(key$decrypt(key$encrypt(r)), r)
    }
  }
  expect_error(key_openssl(k, "quantum"),
               "Invalid encryption mode 'quantum'")
})

test_that("find key", {
  path <- tempfile()
  expect_error(openssl_find_key(path), "file does not exist")
  expect_error(openssl_find_pubkey(path), "file does not exist")
  dir.create(path)
  expect_error(openssl_find_key(path), "did not find id_rsa within")
  expect_error(openssl_find_pubkey(path), "did not find id_rsa.pub within")
})

test_that("default key", {
  if (file.exists("~/.ssh/id_rsa")) {
    expect_equal(openssl_find_key(NULL), "~/.ssh/id_rsa")
  }
  if (file.exists("~/.ssh/id_rsa.pub")) {
    expect_equal(openssl_find_pubkey(NULL), "~/.ssh/id_rsa.pub")
  }

  path <- tempfile()
  oo <- sys_setenv(USER_KEY = path, USER_PUBKEY = path)
  on.exit(sys_resetenv(oo))

  expect_error(openssl_find_key(NULL), "Did not find default ssh private key")
  expect_error(openssl_find_pubkey(NULL), "Did not find default ssh public key")

  ssh_keygen(path, FALSE)
  expect_equal(openssl_find_key(NULL), file.path(path, "id_rsa"))
  expect_equal(openssl_find_pubkey(NULL), file.path(path, "id_rsa.pub"))
})
