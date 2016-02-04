context("openssl")

test_that("basic encryption works", {
  cfg <- config_openssl(OPENSSL_KEY)
  x <- serialize(runif(10), NULL)
  y <- cfg$encrypt(x)
  expect_identical(cfg$decrypt(y), x)
  expect_is(pack_data(y), "raw")
  expect_identical(unpack_data(pack_data(y)), y)
})
