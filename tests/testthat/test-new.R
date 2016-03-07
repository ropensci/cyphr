context("more keys")

## All the different ways of getting things in:

test_that("sodium symmetric", {
  k <- load_key_sodium_symmetric(sodium::keygen())

  path <- tempfile()
  writeBin(as.raw(k), path)
  expect_identical(load_key_sodium_symmetric(path), k)

  x <- make_config(k)

  dat <- serialize(runif(10), NULL)
  secret <- x$encrypt(dat)
  expect_identical(x$decrypt(secret), dat)
})

test_that("sodium pair", {
  k <- sodium::keygen()
  p <- sodium::pubkey(k)

  pair <- load_key_sodium_pair(p, k)
  expect_is(pair, "key_pair")
  expect_is(pair, "sodium_pair")

  x <- make_config(pair)

  dat <- serialize(runif(10), NULL)
  secret <- x$encrypt(dat)
  expect_identical(x$decrypt(secret), dat)

  x <- make_config(pair, FALSE)
  secret <- x$encrypt(dat)
  expect_identical(x$decrypt(secret), dat)

  ## and without a key loaded:
  pair <- load_key_sodium_pair(p, NULL)
  expect_is(pair, "key_pair")
  expect_is(pair, "sodium_pair")

  x <- make_config(pair)
  secret <- x$encrypt(dat)
  expect_error(x$decrypt(secret), "decryption not supported")
})

test_that("openssl", {
  pair <- load_key_openssl(OPENSSL_KEY)
  expect_is(pair, "key_pair")
  expect_is(pair, "rsa_pair")

  x <- make_config(pair)
  expect_is(x, "encryptr_config")
  expect_equal(x$type, "openssl")

  dat <- serialize(runif(10), NULL)
  secret <- x$encrypt(dat)
  expect_identical(x$decrypt(secret), dat)

  ## Non-envelope:
  x2 <- make_config(pair, FALSE)
  secret <- x2$encrypt(dat)
  expect_identical(x2$decrypt(secret), dat)
  expect_error(x2$encrypt(sodium::random(1000)),
               "data too large for key size")
})

test_that("basics", {
  ## TODO: Arrange to loop over all the basic key types here.
  path <- tempfile()
  ssh_keygen(path, FALSE)
  cfg <- config_openssl(path)

  str <- "secret"
  secret <- encrypt_string(str, NULL, cfg)
  expect_is(secret, "raw")
  expect_equal(decrypt_string(secret, cfg), str)

  cfg2 <- config_openssl(path, FALSE)
  secret2 <- encrypt_string(str, NULL, cfg2)
  expect_equal(decrypt_string(secret2, cfg), str)

  expect_error(decrypt_string(secret2, cfg2),
               "decryption not supported")
})
