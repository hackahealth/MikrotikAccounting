"""CHAP (RFC 1994) و MS-CHAPv2 (RFC 2759) و کلیدهای MPPE (RFC 3079)."""
import hashlib
import hmac

from Crypto.Cipher import DES
from Crypto.Hash import MD4

MAGIC1 = b"Magic server to client signing constant"
MAGIC2 = b"Pad to make it do more than one iteration"
MPPE_MASTER = b"This is the MPPE Master Key"
MPPE_MAGIC2 = b"On the client side, this is the send key; on the server side, it is the receive key."
MPPE_MAGIC3 = b"On the client side, this is the receive key; on the server side, it is the send key."
SHS_PAD1 = b"\x00" * 40
SHS_PAD2 = b"\xf2" * 40


def md4(data: bytes) -> bytes:
    return MD4.new(data).digest()


def nt_password_hash(password: str) -> bytes:
    return md4(password.encode("utf-16-le"))


def challenge_hash(peer_challenge: bytes, auth_challenge: bytes, username: str) -> bytes:
    # RFC 2759: domain part must be stripped from the user name
    user = username.split("\\")[-1].encode()
    return hashlib.sha1(peer_challenge + auth_challenge + user).digest()[:8]


def _des_key(key7: bytes) -> bytes:
    bits = int.from_bytes(key7, "big")
    out = bytearray()
    for i in range(8):
        b = (bits >> (56 - 7 * (i + 1))) & 0x7F
        out.append(b << 1)
    return bytes(out)


def challenge_response(challenge: bytes, password_hash: bytes) -> bytes:
    z = password_hash.ljust(21, b"\x00")
    return b"".join(DES.new(_des_key(z[i:i + 7]), DES.MODE_ECB).encrypt(challenge) for i in (0, 7, 14))


def generate_nt_response(auth_challenge, peer_challenge, username, password):
    ch = challenge_hash(peer_challenge, auth_challenge, username)
    return challenge_response(ch, nt_password_hash(password))


def authenticator_response(password, nt_response, peer_challenge, auth_challenge, username) -> str:
    phh = md4(nt_password_hash(password))
    digest = hashlib.sha1(phh + nt_response + MAGIC1).digest()
    ch = challenge_hash(peer_challenge, auth_challenge, username)
    digest = hashlib.sha1(digest + ch + MAGIC2).digest()
    return "S=" + digest.hex().upper()


def mppe_master_key(password, nt_response) -> bytes:
    phh = md4(nt_password_hash(password))
    return hashlib.sha1(phh + nt_response + MPPE_MASTER).digest()[:16]


def mppe_asymmetric_key(master_key, is_send: bool, is_server: bool, length=16) -> bytes:
    if is_send:
        s = MPPE_MAGIC3 if is_server else MPPE_MAGIC2
    else:
        s = MPPE_MAGIC2 if is_server else MPPE_MAGIC3
    return hashlib.sha1(master_key + SHS_PAD1 + s + SHS_PAD2).digest()[:length]


def verify_mschapv2(username, password, auth_challenge: bytes, response: bytes):
    """response = MS-CHAP2-Response attribute (50 bytes).
    Returns (ok, success_attr_bytes, send_key, recv_key)."""
    if len(response) != 50:
        return False, None, None, None
    ident = response[0:1]
    peer_challenge = response[2:18]
    nt_resp = response[26:50]
    expected = generate_nt_response(auth_challenge, peer_challenge, username, password)
    if not hmac.compare_digest(expected, nt_resp):
        return False, None, None, None
    auth_resp = authenticator_response(password, nt_resp, peer_challenge, auth_challenge, username)
    master = mppe_master_key(password, nt_resp)
    send_key = mppe_asymmetric_key(master, is_send=True, is_server=True)
    recv_key = mppe_asymmetric_key(master, is_send=False, is_server=True)
    return True, ident + auth_resp.encode(), send_key, recv_key


def verify_chap(password: str, chap_password: bytes, challenge: bytes) -> bool:
    if len(chap_password) != 17:
        return False
    ident, digest = chap_password[0:1], chap_password[1:]
    return hmac.compare_digest(hashlib.md5(ident + password.encode() + challenge).digest(), digest)
