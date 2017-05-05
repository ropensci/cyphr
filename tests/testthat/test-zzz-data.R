context("data workflow")

test_that("missing user key throws error", {
  expect_error(data_load_keypair_user(tempfile()),
               "file does not exist")
})

test_that("load and reload openssl keypair", {
  pair <- data_load_keypair_user("pair1")
  expect_is(pair, "cyphr_keypair")
  expect_identical(data_load_keypair_user(pair), pair)
})

test_that("require openssl keypair", {
  pair <- structure(list(type = "sodium"), class = "cyphr_keypair")
  expect_error(data_load_keypair_user(pair),
               "Expected an 'openssl' keypair")
})

test_that("user keypair invalid input", {
  expect_error(data_load_keypair_user(1), "Invalid input for 'path_user'")
})

test_that("initialisation requires existing directory", {
  expect_error(data_admin_init(tempfile(), "pair1"),
               "'path_data' must exist and be a directory")
  path <- tempfile()
  writeLines(character(0), path)
  on.exit(file.remove(path))
  expect_error(data_admin_init(path, "pair1"),
               "'path_data' must exist and be a directory")
})

test_that("initialisation", {
  path <- tempfile()
  dir.create(path, FALSE, TRUE)
  quiet <- FALSE
  res <- data_admin_init(path, "pair1", quiet)
  expect_is(res, "cyphr_key")
  expect_true(file.exists(data_path_cyphr(path)))
  expect_true(file.exists(data_path_test(path)))
  expect_identical(decrypt_string(data_path_test(path), res), "cyphr")

  keys <- data_admin_list_keys(path)
  expect_equal(length(keys), 1L)
  expect_is(keys, "data_keys")
  expect_identical(keys[[1]]$pub, data_load_keypair_user("pair1")$pub)

  expect_message(data_request_access(path, "pair1"),
                 "You appear to already have access")

  expect_message(data_admin_init(path, "pair1", quit),
                 "Already set up")
})

test_that("grant access", {
  path <- tempfile()
  dir.create(path, FALSE, TRUE)
  quiet <- FALSE
  res <- data_admin_init(path, "pair1", quiet)
  r <- runif(10)
  encrypt_object(r, res, file.path(path, "data.rds"))

  h <- data_request_access(path, "pair2", quiet)
  expect_message(h2 <- data_request_access(path, "pair2", quiet),
                 "already pending")
  expect_identical(h2, h)

  pair2 <- data_load_keypair_user("pair2")
  expect_identical(h, openssl_fingerprint(pair2$pub))

  ## This is the request:
  path_req <- file.path(data_path_request(path), bin2str(h, ""))
  expect_true(file.exists(path_req))
  dat_req <- readRDS(path_req)
  expect_identical(dat_req$pub, pair2$pub)
  expect_identical(dat_req$host, Sys.info()[["nodename"]])
  expect_identical(dat_req$user, Sys.info()[["user"]])
  expect_is(dat_req$date, "POSIXt")
  expect_true(openssl::signature_verify(data_key_prep(dat_req),
                                        dat_req$signature,
                                        pubkey = dat_req$pub))

  ## Try loading requests:
  keys <- data_load_request(path, NULL, quiet)
  tmp <- keys[[1]]
  tmp$filename <- NULL
  expect_identical(tmp, dat_req)

  expect_identical(data_load_request(path, h), keys)
  expect_identical(data_load_request(path, bin2str(h)), keys)
  expect_identical(data_load_request(path, bin2str(h, "")), keys)

  ## What about nonexistant requests?
  expect_error(data_load_request(path, paste(rep("a", 32), collapse = "")),
               "No key 'a+' found at path")
  expect_error(data_load_request(path, TRUE),
               "Invalid type for 'hash'")

  ans <- data_admin_authorise(path, h, "pair1", TRUE, quiet)

  ## Then the new user can connect:
  k <- data_key(path, "pair2")
  expect_is(k, "cyphr_key")
  expect_identical(k$key(), res$key())

  expect_identical(decrypt_object(file.path(path, "data.rds"), k), r)
})

test_that("git messages", {
  path <- tempfile()
  dir.create(path, FALSE, TRUE)
  dir.create(file.path(path, ".git"), FALSE, TRUE)
  quiet <- FALSE
  res <- data_admin_init(path, "pair1", quiet)

  ## TODO: This path could be improved by relativising the working
  ## directory against the git directory
  res <- testthat::evaluate_promise(data_request_access(path, "pair2", quiet))
  expect_match(res$messages, "If you are using git", all = FALSE)

  res <- evaluate_promise(data_admin_authorise(path, res$value, "pair1",
                                               TRUE, quiet))
  expect_match(res$messages, "If you are using git", all = FALSE)
})

test_that("not set up", {
  path <- tempfile()
  dir.create(path, FALSE, TRUE)
  expect_error(data_key(path, "pair2"), "cyphr not set up for")
  res <- data_admin_init(path, "pair1")
  expect_error(data_key(path, "pair2"),
               "Key file not found; you may not have access")
})

test_that("authorise no keys", {
  path <- tempfile()
  dir.create(path, FALSE, TRUE)
  res <- data_admin_init(path, "pair1")
  expect_message(data_admin_authorise(path, path_user = "pair1"),
                 "No keys to add")
})
