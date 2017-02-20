# apache-hmac-module
Simple apache module for hmac authentication

#Requirements
The build.sh script uses apxs tool for compiling the source code. you can install it on debian-based OSs with the following command:
```
sudo apt-get install apache2-dev
```


#General details
This module generally uses two request headers: X-EPOCH and X-HMAC.
X-EPOCH header will be set by client with the value of current unix timestamp.
X-HMAC is the base64 encoded string of the hashed value of X-EPOCH value using pre-shared key. The pre-shared key is a key
that has same value in the client and the server and it's hard-coded.

This module first examines the difference between X-EPOCH header value and the current unix timestamp in the server to not exceed "maxAllowedDelay" number of seconds which is specified in module configuration.
Then, It will calculate the SHA1 hash of X-EPOCH header with the pre-shared key specified in module configuration to check their equity. In case of failure. it will return HTTP 403 status code.

#Sample configuration
```
<Directory /var/www/>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted

        HatsonHMACEnabled on
        HatsonHMACPreSharedKey "THIS_IS_THE_KEY_SHARED_WITH_CLIENT_AND_SERVER"
        HatsonHMACAllowedRequestDelay 30
</Directory>

```