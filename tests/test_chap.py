from app import chap

AC = bytes.fromhex("5B5D7C7D7B3F2F3E3C2C602132262628")
PC = bytes.fromhex("21402324255E262A28295F2B3A337C7E")
NT = bytes.fromhex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")


def test_rfc2759_vectors():
    assert chap.challenge_hash(PC, AC, "User").hex().upper() == "D02E4386BCE91226"
    assert chap.generate_nt_response(AC, PC, "User", "clientPass") == NT
    assert chap.authenticator_response("clientPass", NT, PC, AC, "User") == "S=407A5589115FD0D6209F510FE9C04566932CDA56"


def test_rfc3079_vectors():
    mk = chap.mppe_master_key("clientPass", NT)
    assert mk.hex().upper() == "FDECE3717A8C838CB388E527AE3CDD31"
    assert chap.mppe_asymmetric_key(mk, True, True).hex().upper() == "8B7CDC149B993A1BA118CB153F56DCCB"


def test_verify_mschapv2():
    resp = b"\x01\x00" + PC + b"\x00" * 8 + NT
    ok, success, sk, rk = chap.verify_mschapv2("User", "clientPass", AC, resp)
    assert ok and success == b"\x01S=407A5589115FD0D6209F510FE9C04566932CDA56"
    assert not chap.verify_mschapv2("User", "wrong", AC, resp)[0]
