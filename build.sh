sudo apxs -i -a -n hmac  -c sha1.h hmac.h base32.h sha1.c hmac.c mod_hmac.c
sudo service apache2 restart