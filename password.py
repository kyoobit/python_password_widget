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
from re import escape, sub, search

try:
    import pytest
except ModuleNotFoundError:
    ## Because I'm lazy and want to keep one file, create a fake handler for
    ## pytest.mark.parametrize used when pytest is not installed. Maybe I'll
    ## consider splitting this into a test file later, or not.
    import functools

    class pytest:
        pass

    class mark:
        def parametrize(func, *args, **kwargs):
            @functools.wraps(func)
            def wrapper_decorator(*args, **kwargs):
                pass

            return wrapper_decorator

    pytest.mark = mark


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
            digest = new(key, msg, digestmod=getattr(hashlib, algorithm))
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


def test_password_baseline():
    value = password(debug=True, key="test", msg="test", no_salt=True, no_date=True)
    print(f"value {type(value)}: {value!r}")
    assert (
        value
        == "Lhi8s|M87M0c(7hdKgC2[wL15KU0<R08;Qfbu~Z54Jc3So84,B87*95d#2z9O\
kf7AWk3j<Fcc&Pfe)X36L39?UUc#2JdJfwf=SS9f*H0Zvb5CYY3,Byd+Aa7Njmd\\x9d)8j4#2i2u~0\
7=SW0j<g4u~l84Jn7$3T6"
    )


def test_password_limit():
    value = password(
        debug=True, key="test", msg="test", no_salt=True, no_date=True, limit=107
    )
    print(f"value {type(value)}: {value!r}")
    assert (
        value
        == "Lhi8s|M87M0c(7hdKgC2[wL15KU0<R08;Qfbu~Z54Jc3So84,B87*95d#2z9Okf7AWk3j<Fcc&Pfe)X36L39?UUc#2JdJfwf=SS9f*H0Zvb"
    )


def test_password_urlsafe():
    value = password(
        debug=True, key="test", msg="test", no_salt=True, no_date=True, limit=107, urlsafe=True
    )
    print(f"value {type(value)}: {value!r}")
    assert (
        value
        == "Lhi8sM87M0c7hdKgC2wL15KU0<R08Qfbu~Z54Jc3So84B8795d#2z9Okf7AWk3j<Fcc&PfeX36L39UUc#2JdJfwf=SS9fH0Zvb5CYY3Byd+"
    )


TEST_DIGESTMOD = [
    (
        "md5",
        "b%zct}UdAWs4MiNbh-y0i;+d:PDcKg0bs|Ue+A40Qmuf_!X41Gn5`#73Fbc8AW2bGcZ9$3\
P7k=U9Tpaf",
    ),
    (
        "sha1",
        "%4D0$3JcXtR9UqR4o^X5(7B1$3X5,Blca$C1+AV5MiueMiK5Jfh0#2699OU5TpLb\\xo8h\
-Naj<88&577Nj8am?45Mi70.DQbq`Xa",
    ),
    (
        "sha224",
        "h-3d)8Td6LY3u~x6BXM3d(d1j<M30Fk1Jfgd$3N3Uq+2[wj4m?88Jfu0XtRd)8mfq`GaMi\
93u~bfKgF23Ice8Nj48Nj6DZb6Zvc1<RLb<RRdMiV6r{AcBX/5,BZ7Ea82\\xI38N58TpGd",
    ),
    (
        "sha256",
        "Lhi8s|M87M0c(7hdKgC2[wL15KU0<R08;Qfbu~Z54Jc3So84,B87*95d#2z9Okf7AWk3j<\
Fcc&Pfe)X36L39?UUc#2JdJfwf=SS9f*H0Zvb5CYY3,Byd+Aa7Njmd\\x9d)8j4#2i2u~07=SW0j<g4\
u~l84Jn7$3T6",
    ),
    (
        "sha384",
        "k=6e^zH88Ny7+AGc@VM8+Ax6'693&5V30F+1o^tfl>75Xtr5p_ZfZvwa@V1d0Fpeq`Me-C\
Zb>Tr6EaM7k=40s|OdOkl6BXD9+A43EaF1%4F9OkwaHdLcWsUcSoPeNj/0@Vne\"1T9Sos4;QF3,Bqe\
TpV0BXF53IS1j<O7OkI0.Dv2EakdOk040Fm3b%AfBXWfUqM9_!RdVrC3#2Vbm?Z0]y65WsUaTpC9Plq\
5!041t}255Kg2",
    ),
    (
        "sha512",
        "Som9\"16b]yHaOk213IMfAW26ZvW3!0m3Wsy6DZv5DZZaFbu6QmRcIejaDZSf6LP6d(Q6>\
T8e(734b%v6?Ul3k=W4p_A8DZVfTpv4Qmq3`#mc]yXdQmreXtefk=s9)8G5]y56i;p09OA15KH5Pl7b\
5Kjei;/aMi19&5F9Hd97#28ak=QdEa/e@VFb+A60m?46b%Ye2HN6\\xo91G90BXQ0*9774Jge%4se$3\
K3Migf8NQf@VM5d(k1b%x7i;Ed'6Zfk=01Njt0[w/f6LGcVr05NjIe.D4b6Ll8<RN63I00BXId_!paU\
qO3o^odt}a4GcM3",
    ),
    (
        "sha3_224",
        "Uqpad(E4:PG4FbZ1\"119.Di9d(rdQmr6Yu82#2kaFb5ej<1bTp0f5KO2KgV4]yTeBXu7&\
5+5NjTd3Iy0'6Ke*9R5AWM5r{D3IeFb:PKb7MheEaO4>Tmf\\xx2f*+2<RH9@V11#273)8A0",
    ),
    (
        "sha3_256",
        "Rnm9n@0b?Up4b%Xa-Ce5f*d7Tpi7LhS9p_hdm?Q8p_b99O22Oks8'6u5s|10@Vl6=SYf/E\
X6\\xwb1GS2e)Ier{Nd.Da6u~L5?U06,Bu1\"1g7/Eic`#R13IL2OkK2Plj0#2kdh-N6,Bi8e)Vbp_Y\
d\\xd29OZe.D+8",
    ),
    (
        "sha3_384",
        '9OS4,Bxb:PZ1JfU6k=P53Iz4g+q3(7Sf[wI3[wkac&v9_!P2u~q2u~J2,BG4;QrbGcUcNj\
kff*6aUqe88NS9Qmk1OklaLhWbn@25IeS2Mil4"1+eWsE9,BTe`#q4_!Wa3Ix4*9k9u~u5#2k6\\xSd\
d(A9"1h2q`p9?UT7MiZei;F1Gce1p_+3p_9aKgp9Yuv6?U9c$316(7y4Hd7bNj8ap_h4`#c4k=68FbJ\
03I38_!H6Zvn9',
    ),
    (
        "sha3_512",
        'o^9fIeC4Soz2SoWcUq5dq`v6MiqeLhK6:Pjf/Efaq`r8DZ6a%4M8;Qedj<uf8NGaj<SfAW\
ja>T+3r{O1)8jeg+hbTpt8?U56Xtw4Ws9a?U63Xtpfu~I8Uq0ep_l8\'6ze4J912Hgbb%d7q`K9CYTc\
2Hv3[wodAWqed(Bah-f9^zX2?UT3c&F4Lht9j<H7"1b3!0if=SH69OZ0c&37Iep4o^Uaf*04;Qbes|b\
fh-MaYuV2"1TaRn706Lc5e)hf/EM56LmdBXU3f*G1g+z6n@Md#2W1EakdLh7bq`g89Od8.Dt7*9x6?U\
n7d(n7TpSal>I5',
    ),
    (
        "blake2s",
        "d(0dRnk24JQ4AWI44Jn0m?u84J09?Usee)1e\\xad8NB2*9Hc<R5d*9z5`#9a;Q70\\xU4\
Rnx72HPe4JH7!0O3l>gfd(L7OkGb8NQ5Mib3d(e1;QL3DZXcb%Z7%4A3QmdaQmD0Gcj2DZkcJf26BXp\
46LY1<RDb%4I7",
    ),
    (
        "blake2b",
        "1GM38Nq2m?ga-C384JV3]yr7g+15q`H6t}+bb%+dLhq4AWG7/E9fUq8bFbPe(7ia&5F8CY\
f6%4of]y87Xtmc_!q3a$1eBXs2-Cm11GK5c&4fh-0a!0O3l>pcm?h9]yEau~7aEard=SL6+Ayc(739)\
8B87M9a'6fe@Vs3ZvI4k=F3Rniae)k9(7m8>T044J34&5FeXtte?Ulbh-72Fbyf`#12Kg/d=S1c!0C1\
Qmcf>Tt5<RXfTpIbHd90:Pf8.DI1BXo60FB2d(69$3r2g+Y62HTd+AE3;Qg75KC1^zm6SoAdDZg9m?E\
7[wxb=Svc-Cjb",
    ),
    (
        "shake_128",
        "WsqaKgZ9;QC9i;G0a$K8/Ei6,Bv2Nj7ag+Y28Nzb5KcfAW/b;Qa6!0R3Eal3DZi79Ob3Pl\
cfs|x6JfU9/ER1OkS9Zv165KE26Ln6i;6dt}7cOkjco^F5\"1E4DZT4)8E59Ob2LhTdBXP4,BP47MW9\
Jfyf0FMat}Me3IZe]ym3f*g1Ok64WsO4)8z4CY7cOkX4)8G6j<id7Mf38NW3e)Mcs|UfYuV57MSb;Qi\
29OR3[wd0:PFcf*a6Uqc6)8P6Zv78Tp23b%Ja$3g3&5Ab=Sw3.DceVrpd0Fa7\\xZ1+ACa!062)8l7d\
(ed!0o6Vrz3Ea91i;G4Gc15!0g5JfP2LhT8k=O9n@F12Hp74Jd4'6r5p_768Np9RnEc#2c3(76f'6Rb\
AW9dUqq8t}n9r{h8#2h0IeB0p_Pc`#c1Hd0c+ATa(7o5g+Ha7Mu6CYK4e)k25KTeUqHap_25<Ra7PlG\
at}a89O9ck=Rf$3UdSof1AW3bIeK5q`V89OS0q`OfCYF4KgDcGcne@VM1k=J6UqL9(7w7Plv6Xtob`#\
ser{we5KO9QmH1'6o1q`Jc/EneCYi9@Vv1f*xf^zv6*93aCY09u~9e6Lv1<Rl8AWw4u~c11Gm3TpidF\
b+c9OIdWs919OA3OkNa8NV0LhT76Lcb-Ck8>TgaIen9QmQ1:PG3!0D1f*/f3Il6t}J6r{J8`#T6i;J6\
\"18bj<fd)8j4^zl52HJ43I77'6jfQms7j<U2WsH9.Do5j<U4g+F8Xtye:PY1_!x4<Rg3q`O9YuDc/E\
7cOkx2l>I4CYybf*sc&5m2#2mf)8Iar{T2FbBc\\x7ce)g0#2pe_!T1<Rkes|e8=SJ2s|96&5v7s|Q8\
'6aa,BMf9O+c<R16Yuff9OTd6Lrfo^N4<Rvfc&16IeWf&5h9^z+7)8T0r{o71Gy2n@M6m?d8Yupb3Io\
e-CZ2PlE3r{NdAWN0(770VrQd`#E5[wc5[ws3!0y7Eaq2Uq/4MiJ89Oi28NS7j<h4Wse0%4V6FbN0$3\
ufDZ8fWsk9?Ux4Mii9d(q2@VO5&5T3s|62#2N7n@pc\"1877MfeYuS3c&o9JfL4#2Y9j<5ee)pe(7q3\
\"1SbNjI16LN49OR1,Bhe/EK8UqP5)8U0a$W5NjNcZvG9<Rh8BX3c&596`#f07M53e)Z8Nj/3h-TeKg\
ffAWk16LI2f*53@VB2n@Ab>To20Fb6$3Q9-CO8DZn8?UV4a$Zcn@u1QmLeJfveIeC0=S4aa$65+Ah3)\
8U9Miu19Ofe6LX2Ok27@Vsd6Lkb",
    ),
    (
        "shake_256",
        'g+2d,BjaFbd37M47f*Z7i;e8"1A6$3P5XtFe^z+0IeB0\\x+f2Hn1)837%46e^z804Jv74\
Jne8N/9]yJf]y37GcreSowbGcYc?Uwb"1Ieh-g7_!FfXtvcm?M9h-Dd<RJe9O3bRnec\'6i1OkF8Jfu\
cOkZ01GC8!0l8WsI0Xt15$3Gbj<qcd(BcIe80p_9cs|s90Ffd-C2dZvIe5KW8PlF8m?L5=SIbq`a9\\\
xP9>Tb0.Dzaf*752HF2TpY3Hd754J61%4NaNjsak=c0(7L7b%+ck=ofLh66Pl5cs|n7BXwfu~26;QH2\
Uqi1%486]yz12HJ4o^Ub>Ts2Ok119OGa:P/3.D/dn@Pb]yFcHdSfBXRbe)Y1Okr5QmS8\\xvea$SfAW\
2a3I131GU65KecMis7]yI0m?WbEaQfSo7aTpD8IeSeXtqbj<990Fe9\'61f2HC0AWpdMif8h-o7t}A8\
[wxbKg1c<RTca$Yc*9V9\'6n55Kx2MiOc?U2dt}A46Lr6SoJf`#If8NEf?U23.Dtcs|q5)8v41G09Pl\
M15Ky6KgZ2CYpb(7c4d(raDZdfr{A4b%wb+Au6NjPdKg85(7e4Xty7t}3an@mc,B/2AWk11GW6l>y4T\
pi3e)CbNj90(7Ydl>m26Lga\\xIb>T2d9Od7*9tbBX55^zd0EaUa7M59k=z7VrTeSoi8<R408Np3(7P\
13I4dp_a5Gcv3"1x6@V91l>95g+L9SopfXty1^zR3PlebUqR6d(X0t}32PlMbd(T2MiC4Eac8-C21Qm\
63a$b6s|3b+AX67M6a&5Rb5KIf,BA4"1l3?US34JK2<RO6"1Y6@Vq9Mic7i;/2c&4be)K7!0k4q`l0R\
nycr{J2WsGe&5Z3t}6fj<Acr{E7DZQb[w/2-CVds|ae+A06j<5fp_we=Sh4-Ca5Uqqb.Dg2&588NjF8\
]yw2NjBf<Rv5LhB8\'6x9+APaZvV0f*52BXg3,Bk6r{87LhC6!0Cd<Rie#2m5&5od$3b5b%x3o^V9"1\
lc$3ZdMi13)8b8\\x1b6L+8TpZam?R43Ixfm?Qep_D1"19ae)Pbl>Rfa$31b%Nf/EG7!0Ld/Eq2MiLe\
EaG94JwcDZ99Fbo13ID7b%z9h-r1!0S5%4Of5KP73I73Fbr1,Bu3CYc07Mo98N6c6LLdf*SbXt+a5KQ\
67M4fDZH7KgP5g+Pf$3Ha+AE4f*s4j<N8!0L0(742,BW5^ze4!0a8)8paLhp3i;Y9&5P8"1aae)v9So\
ec>TZff*Tfc&r8FbZ2Xt6aUqZ42Ha9',
    ),
]


@pytest.mark.parametrize(
    "digestmod, expected", TEST_DIGESTMOD, ids=[test[0] for test in TEST_DIGESTMOD]
)
def test_password_digestmod(digestmod, expected):
    value = password(
        debug=True,
        key="test",
        msg="test",
        no_salt=True,
        no_date=True,
        digestmod=digestmod,
    )
    print(f"value {type(value)}: {value!r}")
    assert value == expected


def random_letters(**kwargs):
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


def test_random_letters_defaults():
    value = random_letters()
    print(f"value {type(value)}: {value!r}")
    assert len(value) == 64
    assert search(f"[{escape(SPECIAL_CHARACTERS)}]", value) is None


def test_random_letters_w_limit():
    value = random_letters(limit=27)
    print(f"value {type(value)}: {value!r}")
    assert len(value) == 27


def random_words(**kwargs):
    """
    limit <int>: limit the output
    """
    ## https://docs.python.org/3/library/secrets.html
    limit = int(kwargs.get("limit", 5))
    if limit < 1:
        limit = 5
    with open(DICTIONARY) as f:
        words = [word.strip() for word in f]
        out = " ".join(secrets.choice(words) for i in range(limit))
    return out


def test_random_words_defaults():
    value = random_words()
    print(f"value {type(value)}: {value!r}")
    assert len(value.split()) == 5


def test_random_words_limit():
    value = random_words(limit=8)
    print(f"value {type(value)}: {value!r}")
    assert len(value.split()) == 8


if __name__ == "__main__":
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
        default=1,
        help="Loop the output as input for N iterations (default=1)",
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

    args = parser.parse_args()

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
