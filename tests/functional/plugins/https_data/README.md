## Generate TLS certificate for HSTS plugin test

If we ever need to generate new certificate for the test, just do the followings:

```
openssl req -new -newkey rsa:1024 -days 365 -nodes -x509 -subj "/C=US/ST=US/L=FOOBAR/O=FOOBAR/CN=localhost" -keyout minion-test.key  -out minion-test.cert
```

Note we need to set the CN to ``localhost`` otherwise cURL will raise error (error
code 51).
