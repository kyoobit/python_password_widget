from pathlib import Path
from re import escape, search

import pytest

from password import DICTIONARY, SPECIAL_CHARACTERS
from password import password
from password import random_letters, random_words
from password import get_arguments, main


def test_password_baseline():
    value = password(debug=True, key="test", msg="test", no_salt=True, no_date=True)
    print(f"value {type(value)}: {value!r}")
    assert (
        value
        == "Lhi8s|M87M0c(7hdKgC2[wL15KU0<R08;Qfbu~Z54Jc3So84,B87*95d#2z9Okf7AWk3j<Fcc&Pfe)X36L39?UUc#2JdJfwf=SS9f*H0Zvb\
5CYY3,Byd+Aa7Njmd\\x9d)8j4#2i2u~07=SW0j<g4u~l84Jn7$3T6"
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


def test_password_salt():
    value = password(
        debug=True, key="test", msg="test", salt="salty", no_date=True, limit=105
    )
    print(f"value {type(value)}: {value!r}")
    assert (
        value
        == 'p_9f,Bj6i;v3&54bg+xfYub8YuBcf*R5p_gbCYE0q`r5l>71\\xr8"1s0f*h4Fb8ag+dfn@bbGceaAWseGcRca$n8^zi7e)ac/EP7Njb5q'
    )


def test_password_no_salt():
    value = password(
        debug=True,
        key="test",
        msg=["test", "test", "test"],
        no_salt=True,
        no_date=True,
        limit=106,
    )
    print(f"value {type(value)}: {value!r}")
    assert (
        value
        == "?UX5BXpePlI9t}T2Iee1c&c3Yu97b%u9;QLcNjMfAWJ6)8jeu~52s|Oc<Rucd(R23I06*9S3a$Be\\x64i;eeNjebZvG9DZx1d(Vda$g1p_"
    )


def test_password_date():
    value = password(
        debug=True,
        key="test",
        msg=["test", "test", "test"],
        no_salt=True,
        date="2024-12-07",
        limit=106,
    )
    print(f"value {type(value)}: {value!r}")
    assert (
        value
        == "f*1d0F07MiF4u~J1Pld4Jf49RnF7\\xj7n@B8^zq1n@f6t}y3c&p0MiQ6:PVaTp77DZnfSo/2-CvaJfw53I803IT5BXi7Ietb<Rs9CYdf]y"
    )


def test_password_unknown_algorithm():
    with pytest.raises(ValueError):
        password(digestmod="unknown")


def test_password_urlsafe():
    value = password(
        debug=True,
        key="test",
        msg="test",
        no_salt=True,
        no_date=True,
        limit=107,
        urlsafe=True,
    )
    print(f"value {type(value)}: {value!r}")
    assert (
        value
        == "Lhi8sM87M0c7hdKgC2wL15KU0<R08Qfbu~Z54Jc3So84B8795d#2z9Okf7AWk3j<Fcc&PfeX36L39UUc#2JdJfwf=SS9fH0Zvb5CYY3Byd+"
    )


def test_password_no_special_characters():
    value = password(
        debug=True,
        key="test",
        msg="test",
        no_salt=True,
        no_date=True,
        limit=107,
        no_special_characters=True,
    )
    print(f"value {type(value)}: {value!r}")
    assert (
        value
        == "Lhi8sM87M0c7hdKgC2wL15KU0R08QfbuZ54Jc3So84B8795d2z9Okf7AWk3jFccPfeX36L39UUc2JdJfwfSS9fH0Zvb5CYY3BydAa7Njmdx"
    )
    assert search(f"[{escape(SPECIAL_CHARACTERS)}]", value) is None


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


def test_random_letters_defaults():
    value = random_letters()
    print(f"value {type(value)}: {value!r}")
    assert len(value) == 64
    assert search(f"[{escape(SPECIAL_CHARACTERS)}]", value) is None


def test_random_letters_w_limit():
    value = random_letters(limit=27)
    print(f"value {type(value)}: {value!r}")
    assert len(value) == 27


def test_random_letters_negative_limit():
    value = random_letters(limit=-1)
    print(f"value {type(value)}: {value!r}")
    assert len(value) == 64


def test_random_words_missing_dictionary():
    with pytest.raises(FileNotFoundError):
        random_words(dictionary="/file/does/not/exist")


@pytest.mark.skipif(
    not Path(DICTIONARY).exists(),
    reason=f"Dictionary file does NOT exist: {DICTIONARY}",
)
def test_random_words_defaults():
    value = random_words()
    print(f"value {type(value)}: {value!r}")
    assert len(value.split()) == 5


@pytest.mark.skipif(
    not Path(DICTIONARY).exists(),
    reason=f"Dictionary file does NOT exist: {DICTIONARY}",
)
def test_random_words_limit():
    value = random_words(limit=8)
    print(f"value {type(value)}: {value!r}")
    assert len(value.split()) == 8


@pytest.mark.skipif(
    not Path(DICTIONARY).exists(),
    reason=f"Dictionary file does NOT exist: {DICTIONARY}",
)
def test_random_words_negative_limit():
    value = random_words(limit=-1)
    print(f"value {type(value)}: {value!r}")
    assert len(value.split()) == 5


TEST_ARGUMENTS = [
    ("msg", "message", "input", ["message", "input"]),
    ("key", "--key", "test", "test"),
    ("key", "-k", "test", "test"),
    ("salt", "--salt", "test", "test"),
    ("salt", "-s", "test", "test"),
    ("no_salt", "--no-salt", None, True),
    ("no_salt", "-S", None, True),
    ("date", "--date", "test", "test"),
    ("date", "-d", "test", "test"),
    ("no_date", "--no-date", None, True),
    ("no_date", "-D", None, True),
    ("digestmod", "--algo", "test", "test"),
    ("digestmod", "-A", "test", "test"),
    ("random_letters", "--letters", None, True),
    ("random_letters", "-L", None, True),
    ("random_words", "--words", None, True),
    ("random_words", "-W", None, True),
    ("urlsafe", "--urlsafe", None, True),
    ("urlsafe", "-U", None, True),
    ("no_special_characters", "--no-special-characters", None, True),
    ("no_special_characters", "-C", None, True),
    ("limit", "--limit", "10", 10),
    ("limit", "--length", "10", 10),
    ("limit", "-l", "10", 10),
    ("iterations", "--iterations", "10", 10),
    ("iterations", "-N", "10", 10),
    ("quiet", "--quiet", None, True),
    ("quiet", "-q", None, True),
    ("debug", "--debug", None, True),
]


@pytest.mark.parametrize(
    "key, flag, value, expected",
    TEST_ARGUMENTS,
    ids=[test[1] for test in TEST_ARGUMENTS],
)
def test_get_arguments(key, flag, value, expected):
    args = get_arguments([flag, value])
    assert getattr(args, key) == expected


def test_main(capsys):
    args = get_arguments(args=["--no-salt", "--no-date", "--key", "test", "test"])
    main(args)
    captured = capsys.readouterr()
    assert (
        captured.out
        == """sha3_384 ---> Wsqak=raEa1bKg0dXtB7(7R4r{j0RnE5OkI1GcC8BXlc^zo46L6\
29Ox01GH2AW/9IeZ6!0Q8Jfde:P4bIe31Wsn1;Q5fPlxfm?r6&515b%c0KgR71G97?UF8Lhhd,BqeYu\
h7!0je"1e7l>K1BXYa0F+f:Pq5g+R7j<z1IeF1+ALfu~k4Wsm57Me8:PH6f*Va(7R8c&W6;QV3.DK7f\
*T8s|VaGcF69On33IAeMisaq`B9OkL1 (240)\n"""
    )
