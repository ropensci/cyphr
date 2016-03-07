context("openssl")

test_that("basic encryption works", {
  cfg <- config_openssl(OPENSSL_KEY)
  x <- serialize(runif(10), NULL)
  y <- cfg$encrypt(x)
  expect_identical(cfg$decrypt(y), x)
  expect_is(pack_data(y), "raw")
  expect_identical(unpack_data(pack_data(y)), y)
})

## Note that this does not do the full encrypted communication like
## sodium can (via sodium::auth_encrypt); only one key at a time is
## used for the encrypt/decrypt step so this is totally prone to a
## message spoofing I believe.  So this is like config_sodium_public.
## To do this properly we'd be looking at signing the message too, I
## think.
test_that("communication", {
  user2 <- tempfile()
  ssh_keygen(user2, FALSE)

  cfg1 <- config_openssl(user2, OPENSSL_KEY)
  cfg2 <- config_openssl(OPENSSL_KEY, user2)

  ## One way:
  x <- runif(10)
  secret <- encrypt_object(x, NULL, cfg1)
  expect_identical(decrypt_object(secret, cfg2), x)

  ## And the other:
  y <- runif(10)
  secret <- encrypt_object(y, NULL, cfg2)
  expect_identical(decrypt_object(secret, cfg1), y)
})

test_that("key locations", {
  user1 <- tempfile()
  user2 <- tempfile()
  ssh_keygen(user1, FALSE)
  ssh_keygen(user2, FALSE)

  on.exit({
    options(encryptr.user.path=NULL)
    Sys.unsetenv("USER_KEY")
    Sys.unsetenv("USER_PUBKEY")
  })

  res1 <- list(pub=file.path(normalizePath(user1), "id_rsa.pub"),
               key=file.path(normalizePath(user1), "id_rsa"))
  res2 <- list(pub=file.path(normalizePath(user2), "id_rsa.pub"),
               key=file.path(normalizePath(user2), "id_rsa"))

  options(encryptr.user.path=user1)
  expect_equal(find_key_openssl(), res1)

  expect_equal(find_key_openssl(private=FALSE),
               c(res1["pub"], key=list(NULL)))
  expect_equal(find_key_openssl(private=user2),
               c(res1["pub"], res2["key"]))

  options(encryptr.user.path=NULL)
  Sys.setenv(USER_KEY=user1, USER_PUBKEY=user2)
  expect_equal(find_key_openssl(private=TRUE), res2)
  expect_equal(find_key_openssl(private=NULL),
               c(res2["pub"], res1["key"]))
})
