# S3 File Manager
S3 file manager for CS 6238.

## Compiling
1. Run `ant`

## Running
For the server:
`java -jar out/artifacts/server_jar/S3Server.jar`

For the client:
`java -jar out/artifacts/client_jar/S3Client.jar [username]`

where `[username]` is either `client1`, `client2`, or `client3`.

Running the test program for `client1` will upload a file (by default, a C file in `/Users/jonathan/swap.c`), delegate it to `client2`, and check it out (and back in).

`client2` will delegate to `client3` and check it out/back in.

`client3` will check out the delegated file.