#!/usr/bin/env Rscript

## See test-reference.R for details and motivation.
zip_dir <- function(path, dest = paste0(basename(path), ".zip")) {
  owd <- setwd(dirname(path))
  on.exit(setwd(owd))
  code <- utils::zip(dest, basename(path), extras = "-q")
  if (code != 0) {
    stop("error running zip")
  }
  normalizePath(dest)
}

version <- packageVersion("cyphr")
path <- file.path("reference", version)
dest <- paste0(path, ".zip")

unlink(path, TRUE)
unlink(dest)

dir.create(path, FALSE, TRUE)
path_openssl <- file.path(path, "openssl")
path_sodium <- file.path(path, "sodium")
path_cypher <- file.path(path, "cypher")
dir.create(path_openssl)
dir.create(path_sodium)
dir.create(path_cypher)

## Generate a lot of keys:
path_openssl_alice <- cyphr::ssh_keygen(file.path(path_openssl, "alice"), FALSE)
path_openssl_bob <- cyphr::ssh_keygen(file.path(path_openssl, "bob"), FALSE)

key_openssl_sym <- openssl::aes_keygen()

key_sodium_sym <- sodium::keygen()

key_sodium_alice <- sodium::keygen()
pub_sodium_alice <- sodium::pubkey(key_sodium_alice)

key_sodium_bob <- sodium::keygen()
pub_sodium_bob <- sodium::pubkey(key_sodium_bob)

saveRDS(key_openssl_sym, file.path(path_openssl, "sym.key"))
writeBin(key_sodium_sym, file.path(path_sodium, "sym.key"))
writeBin(key_sodium_alice, file.path(path_sodium, "alice.key"))
writeBin(pub_sodium_alice, file.path(path_sodium, "alice.pub"))
writeBin(key_sodium_bob, file.path(path_sodium, "bob.key"))
writeBin(pub_sodium_bob, file.path(path_sodium, "bob.pub"))

cleartext <- "test data"

writeBin(
  cyphr::encrypt_string(cleartext, cyphr::key_openssl(key_openssl_sym)),
  file.path(path_cypher, "openssl_sym"))

pair_alice <- cyphr::keypair_openssl(path_openssl_bob, path_openssl_alice)
writeBin(
  cyphr::encrypt_string(cleartext, pair_alice),
  file.path(path_cypher, "openssl_asym_alice"))

writeBin(
  cyphr::encrypt_string(cleartext, cyphr::key_sodium(key_sodium_sym)),
  file.path(path_cypher, "sodium_sym"))

pair_alice <- cyphr::keypair_sodium(pub_sodium_bob, key_sodium_alice)
writeBin(
  cyphr::encrypt_string(cleartext, pair_alice),
  file.path(path_cypher, "sodium_asym_alice"))

writeLines(cleartext, file.path(path, "cleartext"))

path_data <- file.path(path, "data")
dir.create(path_data)
cyphr::data_admin_init(path_data, path_openssl_alice, quiet = TRUE)
filename <- file.path(path_data, "secret.txt")
cyphr::encrypt(writeLines(cleartext, filename),
               cyphr::data_key(path_data, path_openssl_alice))
hash <- cyphr::data_request_access(path_data, path_openssl_bob, quiet = TRUE)
cyphr::data_admin_authorise(path_data, hash, path_openssl_alice,
                            yes = TRUE, quiet = TRUE)

message("Creating archive ", zip_dir(path))
unlink(path, TRUE)
