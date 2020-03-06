## cyphr internal structures

This directory is used by `cyphr` and contains:

* `test` - a small file used to test whether encryption/decrpytion is possible with your key
* Files in `355b345588dc82385acf1cab30ee160e` which are encrypted copies of the (symmetric) data key, encrypted with different users' private keys.  The filename is based on the fingerprint of the private key (see `?openssl::fingerprint`)
* Files in `requests` which are pending requests for access

### Templates

You can create files `template_request` and `template_authorise` within this directory and they will be used to provide feedback when requesting access and authorising keys.  Because this step requires some out-of-band communication this can be useful.
