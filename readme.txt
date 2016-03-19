This program was inspired by http://heise.de/-3112837

Heise reported on how GNU/Linux is lagging behind the state of the art.
This disparity must not stand! Free Software until victory. Always!

--- Intro blablah

This package requires libtommath, which should be available by any sensible
package manager. To use the fancy ./configure menu, you will need dialog. If
you don't have it, or don't want it, use ./configure-ask for a quiz-style
configuration.

Compile with make. This will produce four binaries that have the address of
the server and other details from configure hardcoded (where applicable).
Don't expect bin/shutdown to shut down your local server, if it was built
with 'heise.de' as server address.

--- Binaries blablah

bin/client:   It's what you give to your client (duh).

bin/server:   I'm not really sure what it does. Try running it on a server.
              It will send you a public key on request and a corresponding
              secret key. You'll need to offer a magic number to get the
			  latter, though.

bin/gettok:   Run on the same machine as bin/server. Returns a list of the
              magic numbers that lead to the release of secret keys.

bin/shutdown: Send a shutdown request to the server. You'll need a password.

bin/cc_test:  Takes a magic number and tells you whether it tastes good.
              Not included in the default make target. Use make bin/cc_test

--- Special Thanks

Fabian A. Scherschel -- For inspiring me to write my masterpiece here.
