# Python Password Widget

A Python script that produces hash values based and acts mostly as a wrapper to the Python modules which are wrappers the functionality of OS provided libraries like OpenSSL or LibreSSL.

```shell
usage: password.py [-h] [--key KEY] [--salt SALT] [--no-salt] [--date DATE] 
[--no-date] [--algo DIGESTMOD] [--letters] [--words] [--urlsafe] 
[--no-special-characters] [--limit LIMIT] [--iterations ITERATIONS] [--quiet] 
[--debug] [msg ...]

A silly widget to produce hash values.

positional arguments:
  msg                   Message input values to hash (default='')

options:
  -h, --help            show this help message and exit
  --key, -k KEY         Input key value (salt is added unless --no-salt is used) (default='')
  --salt, -s SALT       Add salt (os.urandom) to the input key (default=True)
  --no-salt, -S         Disable salting (os.urandom) the input key (default=False)
  --date, -d DATE       Append a date value to the input message (default=' 2024-12-07')
  --no-date, -D         Disable append a date value to the input message (default=False)
  --algo, -A DIGESTMOD  Chosen predictable one-way hash algorithm (hashlib digestmod) to use (default='sha3_384')
  --letters, -L         Use random letters instead of a predictable one-way hash algorithm
  --words, -W           Use random words instead of a predictable one-way hash algorithm
  --urlsafe, -U         Remove some special characters considered unsafe for URL usage (default=False)
  --no-special-characters, -C
                        Remove *ALL* special characters (default=False)
  --limit, --length, -l LIMIT
                        Max character length of the hash returned (default=-1 no limit)
  --iterations, -N ITERATIONS
                        Loop the output as input for N iterations (default=1)
  --quiet, -q           Return only the generated hash
  --debug               Show all input values used in the generated hash
```