## cyphr internal structures

This directory is used by `cyphr` and contains:

* `test` - a small file used to test whether encryption/decrpytion is possible with your key
* Files in `keys/` are encrypted copies of the (symmetric) data key, encrypted with different users' public keys.  The filename is based on the fingerprint of the public key (see `?openssl::fingerprint`)
* Files in `requests/` which are pending requests for access

### Templates

You can edit the files `template/request` and `template/authorise` and they will be used to provide feedback when requesting access and authorising keys.  Because this step requires some out-of-band communication this can be useful.

Within the `template/request` template the string `$HASH` will be substituted for your key's hash, and within `template/authorise` the string `$USERS` will contain the usernames of added users.
