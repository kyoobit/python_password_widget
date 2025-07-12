#!/usr/bin/env python3

## alias password='python3 ${HOME}/repos/python/password/password.py $*';

import hashlib
import secrets
import string

from argparse import ArgumentParser
from base64 import b64encode, a85encode, b85encode
from datetime import date
from hmac import new
from os import urandom
from pathlib import Path
from re import escape, sub


ALPHABET = string.ascii_letters + string.digits
DICTIONARY = "/usr/share/dict/words"
SPECIAL_CHARACTERS = "`~!@#$%^&*()_-+={}[]\\|:;\"'<>,.?/"
SPECIAL_CHARACTERS_URLSAFE = "`*()-{}[]\\|:;\"',.?/"


def password(**kwargs) -> str:
    """Return a hash based on input values

    64 is used for os.urandom optional generated `salt' value
    255 is used with shake_* algorithms require a length argument.

    **kwargs:

      key <str>:  Input `key' value use in the hash algorithm
        Default: ''

      msg <str|list>: Input `msg' value use in the hash algorithm
        Default: ''

      salt <str|bool>: Appending a `salt' value to the `key'
        Default: os.urandom(64)

      no_salt <bool>: Disable appending a `salt' value to the `key'
        Default: False

      no_date <bool>: Disable appending a `date' value to the `msg'
        Default: False

      limit <int>: Truncate the resulting hash value to N characters
        Default: -1 (no limit)

      digestmod <str>: Name of the hashlib digestmod algorithm function used
        Default: 'sha256'

    """

    ## Key input
    key = kwargs.get("key", "").encode()

    ## Append additional bytes data to the key
    salt = kwargs.get("salt", "").encode()
    no_salt = kwargs.get("no_salt", False)
    if not salt and not no_salt:
        salt = urandom(64)
        key = key + salt

    ## Message input
    msg = kwargs.get("msg", [])
    if isinstance(msg, list):
        msg = " ".join(msg)

    ## Append additional data to the message
    no_date = kwargs.get("no_date", False)
    if not no_date:
        msg = f"{msg} {kwargs.get('date', date.today())}"

    ## Convert the message string to bytes
    msg = msg.encode()

    ## Algorithm selection
    ## https://docs.python.org/3/library/hashlib.html#hashlib.algorithms_available
    algorithm = kwargs.get("digestmod", "sha256")

    ## shake_* algorithms require a different constructor
    ## https://docs.python.org/3/library/hashlib.html#hashlib.shake_128
    ## https://docs.python.org/3/library/hashlib.html#hashlib.shake_256
    try:
        if algorithm in ["shake_128", "shake_256"]:
            digest = getattr(hashlib, algorithm)(key + salt + msg)
        else:
            digest = new(key, salt + msg, digestmod=getattr(hashlib, algorithm))
    except Exception as err:
        if kwargs.get("debug", False):
            print(f"Exception raised: {err}")
        raise ValueError(f"Unknown algorithm method for {algorithm!r}")

    ## shake_* algorithms require a length argument for the digest
    if algorithm in ["shake_128", "shake_256"]:
        a85 = a85encode(digest.digest(255)).decode()
        b85 = b85encode(digest.digest(255)).decode()
        b64 = b64encode(digest.digest(255)).decode()
        h64 = digest.hexdigest(255)
    else:
        a85 = a85encode(digest.digest()).decode()
        b85 = b85encode(digest.digest()).decode()
        b64 = b64encode(digest.digest()).decode()
        h64 = digest.hexdigest()

    ## Concatenate the encoded values together as the raw value
    raw = "".join(["".join(i) for i in list(zip(a85, b85, b64, h64))])

    ## Remove some special characters from the raw value
    urlsafe = sub(f"[{escape(SPECIAL_CHARACTERS_URLSAFE)}]", "", raw)

    ## Remove ALL special characters from the raw value
    no_special_characters = sub(f"[{escape(SPECIAL_CHARACTERS)}]", "", raw)

    ## Output options
    ## Remove special characters in the hash that are unsafe for use in URLs
    if kwargs.get("urlsafe", False):
        out = urlsafe
    ## Remove ALL special characters in the hash
    elif kwargs.get("no_special_characters", False):
        out = no_special_characters
    ## Return raw hash result
    else:
        out = raw

    ## Limit output character length
    limit = int(kwargs.get("limit", False))
    if limit and limit > 0:
        out = out[:limit]

    ## Debug message
    if kwargs.get("debug", False):
        print(f"{'*' * 40} DEBUG {'*' * 40}")
        print(f"key = {key!r}")
        print(f"salt = {salt!r}")
        print(f"no_salt = {no_salt!r}")
        print(f"no_date = {no_date!r}")
        print(f"msg = {msg!r}")
        print(f"key + salt + msg = ({key!r} + {salt!r} + {msg!r})")
        print(f"algorithm = {algorithm!r}")
        print(f"a85 = {a85!r}")
        print(f"b85 = {b85!r}")
        print(f"b64 = {b64!r}")
        print(f"h64 = {h64!r}")
        print(f"raw = {raw!r} ({len(raw)})")
        print(f"urlsafe = {urlsafe!r} ({len(urlsafe)})")
        print(
            f"no_special_characters = {no_special_characters!r} ({len(no_special_characters)})"
        )
        print(f"limit = {limit}")
        print(f"out = {out!r} ({len(out)})")
        print(f"{'*' * 40} DEBUG {'*' * 40}")

    return out


def random_letters(**kwargs) -> str:
    """
    limit <int>: limit the output
    """
    ## https://docs.python.org/3/library/secrets.html
    while True:
        limit = int(kwargs.get("limit", 64))
        if limit < 1:
            limit = 64
        out = "".join(secrets.choice(ALPHABET) for i in range(limit))
        if (
            any(c.islower() for c in out)
            and any(c.isupper() for c in out)
            and sum(c.isdigit() for c in out) >= 3
        ):
            break
    return out


def random_words(**kwargs) -> str:
    """
    limit <int>: limit the output
    dictionary <str>: Path to a plain text file of dictionary words
        This is normally: /usr/share/dict/words on a *nix system
        Raises FileNotFoundError when missing
    """
    ## https://docs.python.org/3/library/secrets.html
    limit = int(kwargs.get("limit", 5))
    if limit < 1:
        limit = 5
    dictionary = Path(kwargs.get("dictionary", DICTIONARY)).resolve(strict=True)
    with dictionary.open() as f:
        words = [word.strip() for word in f]
    out = " ".join(secrets.choice(words) for i in range(limit))
    return out


def get_arguments(args=None):
    """ """
    parser = ArgumentParser(description="A silly widget to produce hash values.")

    ## TODO: Add post-quantum cryptography (PQC) "quantum-resistant" options

    ## Input options
    parser.add_argument(
        "msg", nargs="*", help="Message input values to hash (default='')"
    )
    parser.add_argument(
        "--key",
        "-k",
        default="",
        help="Input key value (salt is added unless --no-salt is used) (default='')",
    )
    parser.add_argument(
        "--salt",
        "-s",
        default="",
        help="Add salt (os.urandom) to the input key (default=True)",
    )
    parser.add_argument(
        "--no-salt",
        "-S",
        action="store_true",
        help="Disable salting (os.urandom) the input key (default=False)",
    )
    parser.add_argument(
        "--date",
        "-d",
        default=date.today(),
        help=f"Append a date value to the input message (default=' {date.today()}')",
    )
    parser.add_argument(
        "--no-date",
        "-D",
        action="store_true",
        help="Disable append a date value to the input message (default=False)",
    )

    ## Output options
    parser.add_argument(
        "--algo",
        "-A",
        dest="digestmod",
        default="sha3_384",
        help="Chosen predictable one-way hash algorithm (hashlib digestmod) to use (default='sha3_384')",
    )
    parser.add_argument(
        "--letters",
        "-L",
        action="store_true",
        dest="random_letters",
        help="Use random letters instead of a predictable one-way hash algorithm",
    )
    parser.add_argument(
        "--words",
        "-W",
        action="store_true",
        dest="random_words",
        help="Use random words instead of a predictable one-way hash algorithm",
    )
    parser.add_argument(
        "--urlsafe",
        "-U",
        action="store_true",
        help="Remove some special characters considered unsafe for URL usage (default=False)",
    )
    parser.add_argument(
        "--no-special-characters",
        "-C",
        action="store_true",
        help="Remove *ALL* special characters (default=False)",
    )
    parser.add_argument(
        "--limit",
        "--length",
        "-l",
        type=int,
        default=False,
        help="Max character length of the hash returned (default=-1 no limit)",
    )
    parser.add_argument(
        "--iterations",
        "-N",
        type=int,
        default=5000,
        help="Loop the output as input for N iterations (default=5000)",
    )

    ## Display options
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Return only the generated hash"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Show all input values used in the generated hash",
    )

    return parser.parse_args(args)


def main(args):
    ## Use random letters
    if args.random_letters:
        digest = random_letters(**vars(args))
        if not args.quiet:
            print(f"random letters ---> {digest} ({len(digest)})")
        else:
            print(digest)

    ## Use random words
    elif args.random_words:
        digest = random_words(**vars(args))
        if not args.quiet:
            print(f"random words ---> {digest} ({len(digest)})")
        else:
            print(digest)

    ## Use a predictable one-way hash algorithm
    else:

        ## Allow passing the output as input in multiple loops
        iterations = int(args.iterations)
        while iterations > 0:
            digest = password(**vars(args))
            args.key = digest
            iterations = iterations - 1

        if not args.quiet:
            print(f"{args.digestmod} ---> {digest} ({len(digest)})")
        else:
            print(digest)


if __name__ == "__main__":
    arguments = get_arguments()
    main(arguments)
