## All the different ways of getting things in:

test_that("sodium symmetric", {
  k <- key_sodium_symmetric(sodium::keygen())

  path <- tempfile()
  writeBin(as.raw(k), path)
  expect_identical(key_sodium_symmetric(path), k)

  x <- make_config(k)

  dat <- serialize(runif(10), NULL)
  secret <- x$encrypt(dat)
  expect_identical(x$decrypt(secret), dat)
})

test_that("sodium public", {
  k <- sodium::keygen()
  p <- sodium::pubkey(k)

  pair <- key_sodium_public(p, k)
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
  pair <- key_sodium_public(p, NULL)
  expect_is(pair, "key_pair")
  expect_is(pair, "sodium_pair")

  x <- make_config(pair)
  secret <- x$encrypt(dat)
  expect_error(x$decrypt(secret), "decryption not supported")
})

test_that("openssl", {
  pair <- load_key_rsa(OPENSSL_KEY, TRUE)
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
