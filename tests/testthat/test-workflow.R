context("workflow")

test_that("user configuration", {
  path <- tempfile()

  expect_message(res <- data_user_init(path=path),
                 "Creating public key")
  expect_true(file.exists(path))
  expect_true(file.exists(res))

  dat <- data_key_read(res)
  expect_equal(dat$user, Sys.info()[["user"]])
  expect_equal(dat$host, Sys.info()[["nodename"]])
  expect_is(dat$date, "character")
  expect_is(dat$pub, "raw")
  expect_equal(length(dat$pub), 32L)

  ## Running a second time doesn't do anything:
  md5 <- tools::md5sum(res)
  expect_identical(data_user_init(path=path), res)
  expect_identical(tools::md5sum(res), md5)

  ## TODO: support key regeneration here.  But don't do that lightly.
})

test_that("basic workflow", {
  path_us1 <- tempfile("user1_") # user 1 who starts the process
  path_us2 <- tempfile("user2_") # user 2 who is added to the project
  path_dat <- tempfile("data_")
  on.exit(unlink(c(path_us1, path_us2, path_dat), recursive=TRUE))

  data_user_init(path=path_us1)
  data_user_init(path=path_us2)

  ## The data path must exist first.
  expect_error(res <- data_admin_init(path_dat, path_us1),
               "path_data must exist and be a directory")
  dir.create(path_dat)

  expect_message(res <- data_admin_init(path_dat, path_us1),
                 "Generating data key")
  expect_true(res)

  tmp <- data_admin_list_keys(path_dat)
  expect_equal(length(tmp), 1L)
  expect_equal(tmp[[1]]$hash,
               data_hash(data_filename_pub(path_us1)))

  x1 <- config_data(path_dat, path_us1, TRUE)
  expect_is(x1, "encryptr_config")

  expect_error(config_data(path_dat, path_us2, TRUE),
               "Key file not found")

  ## Could try copying the other key over and showing that we can't
  ## use it to decrypt the data.

  ## Then the second user requests access:
  h2 <- data_request_access(path_dat, path_us2)

  ## Now, we can read requests:
  req <- data_admin_list_requests(path_dat)
  expect_equal(names(req), bin2str(h2))

  ## Can load the file by hash in a bunch of ways:
  ## TODO: run this test in previous block.
  tmp <- data_key_load(h2, data_path_request(path_dat))
  expect_identical(data_key_load(bin2str(h2),
                                 data_path_request(path_dat)),
                   tmp)
  expect_identical(data_key_load(bin2str(h2, ""),
                                 data_path_request(path_dat)),
                   tmp)

  data_admin_authorise(req[[1]]$hash, path_dat, path_us1)

  x2 <- config_data(path_dat, path_us2, TRUE)
  expect_is(x2, "encryptr_config")

  rand <- paste(sample(letters), collapse="")
  filename <- file.path(path_dat, "testing")
  encrypt(writeLines(rand, filename), x1)
  expect_identical(decrypt(readLines(filename), x1), rand)
  expect_identical(decrypt(readLines(filename), x2), rand)

  tmp <- data_admin_list_keys(path_dat)
  expect_equal(length(tmp), 2L)

  expect_true(bin2str(data_hash(data_filename_pub(path_us1))) %in% names(tmp))
  expect_true(bin2str(data_hash(data_filename_pub(path_us2))) %in% names(tmp))
})
