from dataclasses import dataclass
from io import BytesIO, StringIO
from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from httpie.context import Environment
from httpie.core import main


@dataclass
class CLIResponse:
    stdout: str
    stderr: str


class MockEnvironment(Environment):
    colors = 0
    show_displays = False
    stdin = None
    stdout_isatty = True
    stderr_isatty = True
    is_windows = False


def http(*args) -> CLIResponse:
    with BytesIO() as stdout, StringIO() as stderr:
        env = MockEnvironment(stdout=stdout, stderr=stderr)
        main(args=['http', *args], env=env)
        stdout.seek(0)
        stderr.seek(0)
        out = stdout.read().decode('utf8')
        err = stderr.read()
        r = CLIResponse(stdout=out, stderr=err)
    return r


@dataclass
class GeneratedKey:
    private_key_pem: bytes
    public_key: Union[RSAPublicKey, EllipticCurvePublicKey]


def generate_key(alg: str):
    if alg.startswith('ES'):
        private_key = ec.generate_private_key(
            curve=ec.SECP192R1(),
            backend=default_backend()
        )
    elif alg.startswith('PS') or alg.startswith('RS'):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    else:
        raise ValueError(f'Unexpected value for alg: {alg}')
    public_key = private_key.public_key()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return GeneratedKey(private_key_pem, public_key)


def generate_jwk():
    return {
        "p": "9Hyo-m_C-k9kN1OlZgt6WErvJjLZk_Abaj2GeTjZLtsS8-kCbFVfeEC_SVC_fs2HvNUhjdUBVbTdY1vhScmIke7KhX4JShIHxaXU97ESmr5-ZpB6zPYLgNug2Zk9hTsdMUGwe9vNM08FWG5wRZnhm3hNYgkd4U3skWzXjhbow1E",
        "kty": "RSA",
        "q": "9AJcXHulq5RuyIfKqPNZvCbYcuF-WCEPLR-wMulI1qDvOfIxFujAS0DbyeZ9dYBJ77teSAtvRmdTX9mBlsEhIwE8wtmDa_T58g-LmgmEvmAG4TlhD6jz4_vz3awGwpSf_Xi4BikMZyQWju378-ZkQ10kMa9Cjn6GFPcSgPRskM8",
        "d": "IGQND500qObnYcJM7v6_noB-ayFMFWzeE8gm87LKFlszYd5RCpWEXljDdUzxM3IvPBiQcMtYOeiOeTsAlDO7GBFNmoEo-J7z_2Ti8VLfDuDCJHZzv5lNJTLWR8KYF8J0qqdBSTY8oQcHjfb6hJ0G8IJpy--9aNfI7FtNJFkyH_geYTj7-Q9-skXSGVjxn1QRtGaLfajbMkAaR3BOcSAJ5NDIoB1b0E4xodJ9ahSk4CacgCPc0NwO5JIy94t_miMSPc3yNxa3tCp2mGVTxUz6kFL8ZPzlB6kPFL-f5JdDApYX6TOUTLlgy9ari30DnjTtiY9WB8cMRyzue55aNGLYAQ",
        "e": "AQAB",
        "qi": "M3iQPXRqUJFFPRdLx_96BAPxnzXMBjuxiINjDataVN-2p5UkMhnOu9gykRZ1YiEa2z0ktIGyq6jCxgPaHn-b43BMGY-jyX6_s0fiL9oxrsTev9JdTdumilxcj2AkNQNBNpvq36SOUOmb14yxfVRgXJCJMKHO5b0p4ne45ecSttY",
        "dp": "SrUVBYHFOKut2eIrdmUne3daYHfFWJlUJ0CpqL0gUFsNDY8z-FqWE67lRMfx3BN92MvftvFRuRjNVaEr1FpK6xzmsafzuriLu2-TBiULpFF1Wm3nuF2u4i86lYNn8yA_KWADR7XAnF8XKRCGKh59e_5k1wImKUSgd0elDnwdoCE",
        "dq": "bVnpfmDDPAOHKkMApXp5SoK2GbXIY0JdhMFgu1Aknlr9GqDZMwUXuCHW3cJ3kwLtH4x-khbdxVVk3d2h36epbACP9Fp6NRVSNhKVY3DElnR-YMzQHK6Arjkpbrw7Q1RL5tIE1m3q6wYXPfKVKRak9DN3lvSOBUHaYObg2f2v8a0",
        "n": "6QkSPSQXjaogBMTCbz3c2aIWNaZsQSaeS2qRkc9gLpzAXgY6Gt0MP8T_MjjWpKqkX4txkxEKVvQ-s4a4e8ZGeg2mGjHb2nPDs1wYAYMohH3Hym7-hXZ3Q78fn5MuThXurqYbJFVMMd0rKCCc9BJPhMJjU3P45Z3gV1m_PaFOWLnrAcacErNbmQJ8PJKKSCGZLdCWf-6A6cPS7f-H5uLuPTU3n7dLkgo8KZcoGl5ZT1dGiLc04qNDZanuDJMwvMyHGRoEvIWh8vu5lmMCcJHy0sLKQsaPaNYQ2Jf-bvxAJPp62U6oZcJNQbUkRi5MQINaS3apWnfIVFnHThejDj9-fw"
    }
