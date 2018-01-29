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
  pair <- keypair_openssl("pair1", "pair1", authenticated = FALSE)
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
  pair <- keypair_openssl("pair1", "pair1", envelope = FALSE,
                          authenticated = FALSE)
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

test_that("pair - auth", {
  pair <- keypair_openssl("pair1", "pair1", authenticated = TRUE)
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

test_that("pair - auth, non envelope", {
  pair <- keypair_openssl("pair1", "pair1", envelope = FALSE,
                          authenticated = TRUE)
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

  key_cbc <- key_openssl(k, "cbc")
  key_ctr <- key_openssl(k, "ctr")
  key_gcm <- key_openssl(k, "gcm")

  expect_identical(key_cbc$decrypt(key_cbc$encrypt(r)), r)
  expect_identical(key_ctr$decrypt(key_ctr$encrypt(r)), r)
  expect_identical(key_gcm$decrypt(key_gcm$encrypt(r)), r)

  expect_error(key_openssl(k, "quantum"),
               "Invalid encryption mode 'quantum'")
})

test_that("find key", {
  path <- tempfile()
  expect_error(openssl_find_key(path), "Private key does not exist")
  expect_error(openssl_find_pubkey(path), "Public key does not exist")
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

test_that("detect incorrect sender", {
  pair_a_auth <- keypair_openssl("pair2", "pair1")
  pair_a_noauth <- keypair_openssl("pair2", "pair1", authenticated = FALSE)

  pair_b <- keypair_openssl("pair1", "pair2")
  pair_c_auth <- keypair_openssl("pair1", "pair3")
  pair_c_noauth <- keypair_openssl("pair1", "pair3", authenticate = FALSE)

  r1 <- openssl::rand_bytes(20)
  r2 <- openssl::rand_bytes(20)
  r3 <- openssl::rand_bytes(20)

  v1 <- pair_b$encrypt(r1)
  v2 <- pair_c_auth$encrypt(r2)
  v3 <- pair_c_noauth$encrypt(r3)

  expect_identical(pair_a_noauth$decrypt(v1), r1)
  expect_identical(pair_a_auth$decrypt(v1), r1)

  expect_identical(pair_a_noauth$decrypt(v2), r2)
  expect_error(pair_a_auth$decrypt(v2),
               "Signatures do not match")

  expect_identical(pair_a_noauth$decrypt(v3), r3)
  expect_error(pair_a_auth$decrypt(v3),
               "Signature missing for encrypyted data")
})

test_that("detect tampering", {
  pair_a_auth <- keypair_openssl("pair2", "pair1")
  pair_a_noauth <- keypair_openssl("pair2", "pair1", authenticated = FALSE)
  pair_b <- keypair_openssl("pair1", "pair2")
  pair_c <- keypair_openssl("pair1", "pair3", authenticated = FALSE)

  r1 <- openssl::rand_bytes(20)
  r2 <- openssl::rand_bytes(20)
  v1 <- pair_b$encrypt(r1)
  v2 <- pair_c$encrypt(r2)

  expect_identical(pair_a_noauth$decrypt(v1), r1)
  expect_identical(pair_a_auth$decrypt(v1), r1)

  ## Then tamper with the message
  tmp <- unserialize(v2)
  tmp$signature <- unserialize(v1)$signature
  v3 <- serialize(tmp, NULL)

  expect_identical(pair_a_noauth$decrypt(v3), r2)
  expect_error(pair_a_auth$decrypt(v3),
               "Signatures do not match")
})
