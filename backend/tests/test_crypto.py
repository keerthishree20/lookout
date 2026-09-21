import pytest

from lookout.crypto import (
    Ed25519Signer,
    MLDSASigner,
    MLKEMSealer,
    X25519Sealer,
    build_sealer,
    build_signer,
    crypto_status,
)


def test_default_signer_is_ml_dsa_and_quantum_safe():
    signer = build_signer()
    assert isinstance(signer, MLDSASigner)
    assert signer.algorithm == "ML-DSA-65"
    assert signer.quantum_safe


def test_ml_dsa_signature_verifies_and_rejects_altered_message():
    signer = MLDSASigner()
    sig = signer.sign(b"decision 42: block_and_alert")
    assert signer.verify(b"decision 42: block_and_alert", sig)
    assert not signer.verify(b"decision 42: allow", sig)


def test_ml_dsa_rejects_corrupted_signature():
    signer = MLDSASigner()
    sig = bytearray(signer.sign(b"payload"))
    sig[10] ^= 0xFF
    assert not signer.verify(b"payload", bytes(sig))


def test_ml_dsa_seeded_keygen_is_deterministic():
    seed = b"s" * 32
    assert MLDSASigner(seed).public_key == MLDSASigner(seed).public_key
    assert MLDSASigner(seed).public_key != MLDSASigner(b"t" * 32).public_key


def test_ml_dsa_key_sizes_match_fips_204_category_3():
    signer = MLDSASigner()
    assert len(signer.public_key) == 1952
    assert len(signer.sign(b"x")) == 3309


def test_classical_fallback_when_pqc_not_preferred():
    signer = build_signer(prefer_pqc=False)
    assert isinstance(signer, Ed25519Signer)
    assert not signer.quantum_safe
    sig = signer.sign(b"m")
    assert signer.verify(b"m", sig) and not signer.verify(b"n", sig)


@pytest.mark.parametrize("sealer_cls", [MLKEMSealer, X25519Sealer])
def test_seal_roundtrip(sealer_cls):
    sealer = sealer_cls()
    blob = sealer.seal(b"swift-gateway-api-key", aad=b"vault/swift")
    assert sealer.unseal(blob, aad=b"vault/swift") == b"swift-gateway-api-key"
    assert b"swift-gateway" not in blob.ciphertext.encode()


@pytest.mark.parametrize("sealer_cls", [MLKEMSealer, X25519Sealer])
def test_seal_is_bound_to_its_name(sealer_cls):
    """Moving a sealed blob to a different vault path must not decrypt."""
    sealer = sealer_cls()
    blob = sealer.seal(b"secret", aad=b"vault/a")
    with pytest.raises(Exception):
        sealer.unseal(blob, aad=b"vault/b")


def test_each_seal_uses_a_fresh_encapsulation():
    sealer = MLKEMSealer()
    a = sealer.seal(b"same")
    b = sealer.seal(b"same")
    assert a.kem_ciphertext != b.kem_ciphertext
    assert a.ciphertext != b.ciphertext


def test_status_reports_fully_quantum_safe_only_when_both_are():
    assert crypto_status(build_signer(), build_sealer())["fully_quantum_safe"]
    mixed = crypto_status(build_signer(prefer_pqc=False), build_sealer())
    assert not mixed["fully_quantum_safe"]
    assert mixed["signing"]["algorithm"] == "Ed25519"
