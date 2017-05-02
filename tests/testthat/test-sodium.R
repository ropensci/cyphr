context("sodium")

test_that("pair", {
  key <- sodium::keygen()
  pub <- sodium::pubkey(key)

  pair <- keypair_sodium(pub, key)

  expect_is(pair, "cyphr_key")
  expect_equal(pair$type, "sodium")
  expect_is(pair$pub, "raw")
  expect_is(pair$key, "function")
  expect_is(pair$key(), "raw")
  expect_is(pair$encrypt, "function")
  expect_is(pair$decrypt, "function")

  r <- openssl::rand_bytes(20)
  v <- pair$encrypt(r)
  expect_is(v, "raw")
  expect_gt(length(v), length(r))
  expect_identical(pair$decrypt(v), r)
})

test_that("pair (authenticated)", {
  key <- sodium::keygen()
  pub <- sodium::pubkey(key)

  pair <- keypair_sodium(pub, key, TRUE)

  expect_is(pair, "cyphr_key")
  expect_equal(pair$type, "sodium")
  expect_is(pair$pub, "raw")
  expect_is(pair$key, "function")
  expect_is(pair$key(), "raw")
  expect_is(pair$encrypt, "function")
  expect_is(pair$decrypt, "function")

  r <- openssl::rand_bytes(20)
  v <- pair$encrypt(r)
  expect_is(v, "raw")
  expect_gt(length(v), length(r))
  expect_identical(pair$decrypt(v), r)
})

test_that("pair (communicate)", {
  key1 <- sodium::keygen()
  key2 <- sodium::keygen()
  pub1 <- sodium::pubkey(key1)
  pub2 <- sodium::pubkey(key2)

  r <- openssl::rand_bytes(20)

  for (auth in c(FALSE, TRUE)) {
    pair1 <- keypair_sodium(pub2, key1, auth)
    pair2 <- keypair_sodium(pub1, key2, auth)
    v <- pair1$encrypt(r)
    expect_identical(pair2$decrypt(v), r)
    expect_identical(pair1$decrypt(pair2$encrypt(r)), r)
    session_key_refresh()
    expect_error(pair2$decrypt(v), "Failed to decrypt")
  }
})

test_that("symmetric", {
  k <- sodium::keygen()
  key <- key_sodium(k)
  expect_is(key$key, "function")
  expect_identical(key$key(), k)

  r <- openssl::rand_bytes(20)
  v <- key$encrypt(r)
  expect_is(v, "raw")
  expect_gt(length(v), length(r))
  expect_identical(key$decrypt(v), r)
})

test_that("sodium_load_key", {
  expect_error(sodium_load_key(NULL), "raw vector or a file")
  expect_error(sodium_load_key(raw(12)), "Unexpected length")
  path <- tempfile()
  k <- sodium::keygen()
  writeBin(k, path)
  expect_identical(sodium_load_key(path), k)
})

test_that("print", {
  key <- sodium::keygen()
  pub <- sodium::pubkey(key)
  expect_output(print(keypair_sodium(pub, key)), "<cyphr_keypair: sodium>",
                fixed = TRUE)
  expect_output(print(key_sodium(key)), "<cyphr_key: sodium>",
                fixed = TRUE)
})
