context("data workflow")

test_that("missing user key throws error", {
  expect_error(data_load_keypair_user(tempfile()),
               "key does not exist")
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

  expect_message(data_admin_init(path, "pair1", quiet),
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
  expect_identical(h, data_key_fingerprint(pair2$pub, data_schema_version()))

  ## This is the request:
  path_req <- file.path(data_path_request(path), bin2str(h, ""))
  expect_true(file.exists(path_req))
  dat_req <- readRDS(path_req)
  expect_identical(dat_req$pub, pair2$pub)
  expect_identical(dat_req$host, Sys.info()[["nodename"]])
  expect_identical(dat_req$user, Sys.info()[["user"]])
  expect_is(dat_req$date, "POSIXt")

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

  res <- testthat::evaluate_promise(data_request_access(path, "pair2", quiet))
  expect_match(res$messages, "If you are using git", all = FALSE)

  res <- evaluate_promise(
    data_admin_authorise(path, res$value, "pair1", TRUE, quiet))
  expect_match(res$messages, "If you are using git", all = FALSE)
})

test_that("not set up", {
  path <- tempfile()
  dir.create(path, FALSE, TRUE)
  expect_error(data_key(path, "pair2"), "cyphr not set up for")
  expect_error(
    with_dir(path, data_key(NULL, "pair2")),
    "cyphr not set up for")
  expect_error(
    with_dir(path, data_key(path_user = "pair2")),
    "cyphr not set up for")
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

test_that("cancel auth", {
  path <- tempfile()
  dir.create(path, FALSE, TRUE)
  res <- data_admin_init(path, "pair1")
  h <- data_request_access(path, "pair2")

  testthat::with_mock(
    `cyphr:::prompt_confirm` = function() FALSE,
    expect_message(try(data_admin_authorise(path, h, "pair1", FALSE),
                       silent = TRUE),
                   "Cancelled adding key"),
    expect_error(data_admin_authorise(path, h, "pair1", FALSE),
                 "Errors adding 1 key"))
})

test_that("print keys", {
  path <- tempfile()
  dir.create(path, FALSE, TRUE)
  res <- data_admin_init(path, "pair1")

  expect_output(print(data_admin_list_requests(path)), "(empty)",
                fixed = TRUE)
  msg <- capture.output(print(data_admin_list_keys(path)))
  expect_match(msg[[1]], "1 key:")

  h <- data_request_access(path, "pair2")
  ans <- data_admin_authorise(path, h, "pair1", TRUE)

  msg <- capture.output(print(data_admin_list_keys(path)))
  expect_match(msg[[1]], "2 keys:")
})

test_that("detect tampering", {
  path <- tempfile()
  dir.create(path, FALSE, TRUE)
  res <- data_admin_init(path, "pair1")

  ## Here's the request:
  h <- data_request_access(path, "pair2")

  ## Here's the attacker:
  pair3 <- data_load_keypair_user("pair3")

  path_req <- data_path_request(path)
  path_use <- file.path(path_req, bin2str(h, ""))
  expect_true(file.exists(path_use))
  dat <- readRDS(path_use)

  ## Try adding our own key here:
  dat$pub <- pair3$pub
  saveRDS(dat, path_use)

  expect_error(data_admin_authorise(path, h, "pair1", TRUE, quiet),
               "Public key hash disagrees for")
})

test_that("decryption failed gives reasonable error", {
  path1 <- tempfile()
  path2 <- tempfile()
  dir.create(path1, FALSE, TRUE)
  dir.create(path2, FALSE, TRUE)
  res1 <- data_admin_init(path1, "pair1")
  res2 <- data_admin_init(path2, "pair1")
  file.copy(data_path_test(path1), data_path_test(path2), overwrite = TRUE)
  expect_error(data_key(path2, "pair1"),
               "Decryption failed")
})

test_that("gracefully fail to initialise", {
  path <- tempfile()
  dir.create(path, FALSE, TRUE)
  testthat::with_mock(
    `cyphr:::data_authorise_write` = function(...) stop("Unexplained error"),
    expect_message(try(data_admin_init(path, "pair1"), silent = TRUE),
                   "Removing data key"))
  expect_equal(dir(data_path_cyphr(path), all.files = TRUE, no.. = TRUE),
               character(0))
})


## This set of tests verifies that if we call the data functions
## (except for init) we can use a subdirectory of the cyphr
## directories without a problem.
test_that("Work from a subdirectory", {
  path <- tempfile()
  dir.create(path, FALSE, TRUE)
  res <- data_admin_init(path, "pair1", TRUE)
  sub <- file.path(path, "a/b/c")
  dir.create(sub, FALSE, TRUE)
  ## Need full paths to keys as they will be in a surprising location
  ## otherwise.
  pair1 <- normalizePath("pair1")
  pair2 <- normalizePath("pair2")

  h <- with_dir(sub,
                data_request_access(path_user = pair2))

  res <- with_dir(sub, data_admin_list_requests())
  expect_equal(length(res), 1L)
  expect_equal(names(res), unclass(as.character(h)))

  with_dir(sub,
           data_admin_authorise(path_user = pair1, yes = TRUE))

  res <- with_dir(sub, data_admin_list_keys())
  expect_equal(length(res), 2L)

  k1 <- with_dir(sub, data_key(path_user = pair1))
  k2 <- with_dir(sub, data_key(path_user = pair2))
  expect_identical(k1$key(), k2$key())
})


test_that("Custom messages", {
  path <- tempfile()
  dir.create(path, FALSE, TRUE)
  res <- data_admin_init(path, "pair1", TRUE)

  writeLines("my custom $HASH request message",
             file.path(data_path_template(path), "request"))
  writeLines("my custom $USERS authorise message",
             file.path(data_path_template(path), "authorise"))

  res1 <- testthat::evaluate_promise(
    data_request_access(path, "pair2"))
  res2 <- testthat::evaluate_promise(
    data_admin_authorise(path, res1$result, "pair1", TRUE))

  expect_match(
    res1$messages,
    "my custom [[:xdigit:]:]+ request message",
    all = FALSE)
  expect_match(
    res2$messages,
    "my custom .+ authorise message",
    all = FALSE)
})


test_that("fingerprint versioning", {
  k <- data_load_keypair_user("pair1")$pub
  expect_identical(
    data_key_fingerprint(k, numeric_version("1.0.3")),
    openssl::fingerprint(k, openssl::md5))
  expect_identical(
    data_key_fingerprint(k, numeric_version("1.1.0")),
    openssl::fingerprint(k, openssl::sha256))
})


test_that("schema validation - old version produces warning the first time", {
  path <- unzip_reference("reference/1.0.0.zip")
  path_data <- file.path(path, "data")
  path_openssl_alice <- file.path(path, "openssl", "alice")

  expect_warning(
    data_version_read(path_data),
    "Your cyphr schema version is out of date (found 1.0.0, current is 1.1.0)",
    fixed = TRUE)
  expect_silent(
    data_version_read(path_data))
})


test_that("migrate", {
  path <- unzip_reference("reference/1.0.0.zip")
  path_data <- file.path(path, "data")
  path_openssl_alice <- file.path(path, "openssl", "alice")
  path_openssl_bob <- file.path(path, "openssl", "bob")
  suppressWarnings(data_version_read(path_data))

  data_request_access(path_data, "pair3")

  keys_old <- data_admin_list_keys(path_data)
  reqs_old <- data_admin_list_requests(path_data)

  res <- testthat::evaluate_promise(data_schema_migrate(path_data))
  expect_match(res$messages, "Migrating key", all = FALSE)
  expect_match(res$messages, "Migrating request", all = FALSE)

  keys_new <- data_admin_list_keys(path_data)
  reqs_new <- data_admin_list_requests(path_data)

  map <- vapply(keys_old, function(k)
    bin2str(data_key_fingerprint(k$pub, data_schema_version()), ""), "")

  expect_setequal(names(keys_new), unname(map))
  v <- c("user", "host", "date", "pub", "key")
  for (i in seq_along(map)) {
    expect_equal(keys_old[[i]][v], keys_new[[map[[i]]]][v])
  }

  key1 <- data_key(path_data, path_openssl_alice)
  key2 <- data_key(path_data, path_openssl_bob)
  expect_identical(key1$key(), key2$key())

  data_admin_list_requests(path_data)
  data_admin_authorise(path_data, path_user = path_openssl_alice, yes = TRUE)
  key3 <- data_key(path_data, "pair3")

  expect_identical(key1$key(), key3$key())

  res <- testthat::evaluate_promise(data_schema_migrate(path_data))
  expect_match(res$messages, "Everything up to date!")
})


test_that("schema validation - new version errors", {
  path <- tempfile()
  dir.create(path, FALSE)
  res <- data_admin_init(path, "pair1")
  writeLines("9.9.9", data_path_version(path))
  data_pkg_init() # clear cache
  expect_error(
    data_version_read(path),
    "Upgrade to cyphr version 9.9.9 (or newer)",
    fixed = TRUE)
})


test_that("new data sources do not need migrating", {
  path <- tempfile()
  dir.create(path, FALSE)
  data_admin_init(path, "pair1")
  res <- testthat::evaluate_promise(data_schema_migrate(path))
  expect_match(res$messages, "Everything up to date!")
})


test_that("cache data key", {
  path <- tempfile()
  dir.create(path, FALSE)
  data_admin_init(path, "pair1")

  key1 <- data_key(path, "pair1")
  key2 <- data_key(path, "pair1")
  key3 <- data_key(path, "pair1", cache = FALSE)
  expect_identical(key1, key2)
  expect_false(identical(key1, key3))
})
