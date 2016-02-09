context("workflow")

test_that("user configuration", {
  expect_error(data_check_path_user(tempfile()),
               "Key does not exist")
  expect_is(data_check_path_user(OPENSSL_KEY), "rsa_pair")

  path2 <- tempfile()
  ssh_keygen(path2, FALSE)
  path2 <- normalizePath(path2)
  tmp <- data_check_path_user(path2, TRUE)
  expect_identical(tmp$dir, path2)

  oo <- options("encryptr.user.path"=path2)
  on.exit(options(oo))
  expect_equal(dirname(data_path_user(NULL)), path2)
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
  expect_equal(names(tmp)[[1]],
               bin2str(data_hash(file.path(path_us1, "id_rsa.pub")), ""))

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

  expect_true(bin2str(data_hash(file.path(path_us1, "id_rsa.pub")), "")
              %in% names(tmp))
  expect_true(bin2str(data_hash(file.path(path_us2, "id_rsa.pub")), "")
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

test_that("read non-existant key", {
  path <- tempfile()
  expect_error(read_public_key(path), "Public key not found")
  expect_error(read_private_key(path), "Key not found")
  expect_error(change_password(path, password=FALSE), "Key not found")
})
