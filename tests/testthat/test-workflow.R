context("workflow")

test_that("user configuration", {
  expect_error(data_check_path_user(tempfile()),
               "Key does not exist")
  expect_is(data_check_path_user(OPENSSL_KEY), "rsa_pair")

  path2 <- tempfile()
  ssh_keygen(path2, FALSE)
  path2 <- normalizePath(path2)
  tmp <- data_check_path_user(path2, TRUE)
  expect_identical(tmp$path$dir, path2)

  oo <- options("encryptr.user.path"=path2)
  on.exit(options(oo))
  expect_equal(dirname(data_path_user(NULL)), path2)
  expect_equal(dirname(data_path_user(OPENSSL_KEY)),
               normalizePath(OPENSSL_KEY))
  expect_error(data_path_user(tempfile()),
               "Key does not exist")
})

test_that("basic workflow", {
  path_us1 <- tempfile("user1_") # user 1 who starts the process
  path_us2 <- tempfile("user2_") # user 2 who is added to the project
  path_dat <- tempfile("data_")
  on.exit(unlink(c(path_us1, path_us2, path_dat), recursive=TRUE))

  temporary_key(path_us1)
  temporary_key(path_us2)

  ## The data path must exist first.
  expect_error(res <- data_admin_init(path_dat, path_us1),
               "path_data must exist and be a directory")

  dir.create(path_dat)
  expect_message(res <- data_admin_init(path_dat, path_us1),
                 "Generating data key")
  expect_true(res)

  tmp <- data_admin_list_keys(path_dat)
  expect_equal(length(tmp), 1L)
  expect_identical(tmp[[1]]$pub, load_key_ssl(path_us1, FALSE)$pub)
  expect_identical(names(tmp),
                   bin2str(openssl_fingerprint(tmp[[1]]$pub), ""))

  x1 <- config_data(path_dat, path_us1, TRUE)
  expect_is(x1, "encryptr_config")
  ## TODO: perhaps this should be sodium_symmetric
  expect_equal(x1$type, "symmetric")

  expect_error(config_data(path_dat, path_us2, TRUE),
               "Key file not found")

  ## Could try copying the other key over and showing that we can't
  ## use it to decrypt the data.

  ## Then the second user requests access:
  h2 <- data_request_access(path_dat, path_us2)
  expect_message(data_request_access(path_dat, path_us2),
                 "Request is already pending")

  ## Now, we can read requests:
  req <- data_admin_list_requests(path_dat)
  expect_equal(names(req), bin2str(h2, ""))

  ## Can load the file by hash in a bunch of ways:
  ## TODO: run this test in previous block.
  tmp <- data_pub_load(h2, data_path_request(path_dat))
  ## TODO: What is this test showing?
  expect_identical(data_pub_load(bin2str(h2),
                                 data_path_request(path_dat)),
                   tmp)
  expect_identical(data_pub_load(bin2str(h2, ""),
                                 data_path_request(path_dat)),
                   tmp)

  data_admin_authorise(path_dat, path_user=path_us1, yes=TRUE)

  x2 <- config_data(path_dat, path_us2, TRUE)
  expect_is(x2, "encryptr_config")

  rand <- paste(sample(letters), collapse="")
  filename <- file.path(path_dat, "testing")
  encrypt(writeLines(rand, filename), x1)
  expect_identical(decrypt(readLines(filename), x1), rand)
  expect_identical(decrypt(readLines(filename), x2), rand)

  tmp <- data_admin_list_keys(path_dat)
  expect_equal(length(tmp), 2L)

  expect_true(bin2str(openssl_fingerprint(tmp[[1]]$pub), "") %in% names(tmp))
  expect_true(bin2str(openssl_fingerprint(tmp[[2]]$pub), "") %in% names(tmp))

  expect_true(bin2str(
    openssl_fingerprint(
      openssl::read_pubkey(file.path(path_us1, "id_rsa.pub"))), "")
    %in% names(tmp))
  expect_true(bin2str(
    openssl_fingerprint(
      openssl::read_pubkey(file.path(path_us2, "id_rsa.pub"))), "")
    %in% names(tmp))
})

test_that("out-of-order init", {
  path_us1 <- tempfile("user1_") # user 1 who starts the process
  path_us2 <- tempfile("user2_") # user 2 who is added to the project
  path_dat <- tempfile("data_")
  on.exit(unlink(c(path_us1, path_us2, path_dat), recursive=TRUE))

  temporary_key(path_us1)
  temporary_key(path_us2)
  dir.create(path_dat)

  expect_message(res <- data_admin_init(path_dat, path_us1),
                 "Generating data key")
  expect_true(res)
  expect_error(data_admin_init(path_dat, path_us2, quiet=TRUE),
               "you may not have access")
  expect_error(data_admin_init(path_dat, path_us2, quiet=TRUE),
               "data_request_access")
})

test_that("request access", {
  path_us1 <- tempfile("user1_") # user 1 who starts the process
  path_us2 <- tempfile("user2_") # user 2 who is added to the project
  path_dat <- tempfile("data_")
  on.exit(unlink(c(path_us1, path_us2, path_dat), recursive=TRUE))

  temporary_key(path_us1)
  temporary_key(path_us2)
  dir.create(path_dat)

  res <- data_admin_init(path_dat, path_us1)

  oo <- options(encryptr.user.path=path_us2)
  on.exit(options(oo))

  hash <- data_request_access(path_dat)
})

test_that("authorise specific key", {
  path_us1 <- tempfile("user1_") # user 1 who starts the process
  path_us2 <- tempfile("user2_") # user 2 who is added to the project
  path_us3 <- tempfile("user3_") # user 2 who is added to the project
  path_dat <- tempfile("data_")
  on.exit(unlink(c(path_us1, path_us2, path_us3, path_dat), recursive=TRUE))

  temporary_key(path_us1)
  temporary_key(path_us2)
  temporary_key(path_us3)
  dir.create(path_dat)

  res <- data_admin_init(path_dat, path_us1)
  hash2 <- data_request_access(path_dat, path_us2)
  expect_true(data_admin_authorise(path_dat, hash2, path_us1, yes=TRUE))

  hash3 <- data_request_access(path_dat, path_us2)
  expect_true(data_admin_authorise(path_dat, hash3, bin2str(path_us2), yes=TRUE))
})
