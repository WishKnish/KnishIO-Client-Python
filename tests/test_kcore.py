# -*- coding: utf-8 -*-
"""
libkcore binding tests (knishioclient/libraries/kcore.py).

The parity tests run only where the library loads (a platform wheel, or a checkout after
`python scripts/fetch_kcore.py --host`); the vector suites cover the SDK paths in both modes, since
CI runs pytest with KNISHIO_KCORE=require and =off. These tests pin what those suites cannot:
kcore and the pure-Python loops agree on arbitrary keys, encapsulation never repeats, inputs kcore
does not take fall back instead of failing, and the KNISHIO_KCORE modes behave as documented.
"""

import hashlib
import json
import os
import sys
import unittest
from pathlib import Path

SDK_ROOT = str(Path(__file__).resolve().parent.parent)
if SDK_ROOT not in sys.path:
    sys.path.insert(0, SDK_ROOT)

from knishioclient.libraries import kcore
from knishioclient.models.MoleculeStructure import MoleculeStructure
from knishioclient.models.Wallet import Wallet

VECTORS = json.load(open(Path(__file__).parent / "fixtures" / "cross-platform-test-vectors.json",
                         encoding="utf-8"))["vectors"]
ENV_KEYS = ("KNISHIO_KCORE", "KNISHIO_KCORE_LIB")


class KcoreTestCase(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in ENV_KEYS}
        kcore._reset()

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        kcore._reset()

    def pure(self, fn, *args):
        """fn(*args) with libkcore switched off, then the environment restored."""
        saved = os.environ.get("KNISHIO_KCORE")
        os.environ["KNISHIO_KCORE"] = "off"
        kcore._reset()
        try:
            return fn(*args)
        finally:
            if saved is None:
                os.environ.pop("KNISHIO_KCORE", None)
            else:
                os.environ["KNISHIO_KCORE"] = saved
            kcore._reset()

    def require_kcore(self):
        if os.environ.get("KNISHIO_KCORE", "auto").lower() == "off" or not kcore.available():
            self.skipTest("libkcore is not loaded")


class ParityTest(KcoreTestCase):
    def test_wots_address_matches_pure_python(self):
        self.require_kcore()
        for i in range(20):
            key = hashlib.shake_256(str(i).encode()).hexdigest(1024)
            with self.subTest(i=i):
                self.assertEqual(self.pure(Wallet.generate_address, key), kcore.wots_address(key))

    def test_signature_fragments_match_pure_python_both_directions(self):
        self.require_kcore()
        for t in VECTORS["wots_signature"]["tests"]:
            mol = MoleculeStructure()
            mol.molecularHash = t["molecularHash"]
            for encode in (True, False):
                with self.subTest(name=t["name"], encode=encode):
                    fast = mol.signature_fragments(t["privateKey"], encode)
                    self.assertEqual(self.pure(mol.signature_fragments, t["privateKey"], encode), fast)

    def test_encapsulation_never_repeats(self):
        self.require_kcore()
        seed = hashlib.shake_256(b"kcore-encaps-freshness").digest(64)
        for name, keypair, encaps, decaps in (
            ("1024", kcore.mlkem1024_keypair, kcore.mlkem1024_encaps, kcore.mlkem1024_decaps),
            ("768", kcore.mlkem768_keypair, kcore.mlkem768_encaps, kcore.mlkem768_decaps),
        ):
            with self.subTest(set=name):
                pk, sk = keypair(seed)
                ct1, ss1 = encaps(pk)
                ct2, ss2 = encaps(pk)
                self.assertNotEqual(ct1, ct2)
                self.assertNotEqual(ss1, ss2)
                self.assertEqual(ss1, decaps(ct1, sk))
                self.assertEqual(ss2, decaps(ct2, sk))


class IneligibleInputTest(KcoreTestCase):
    """Inputs kcore does not take return None, so callers keep their existing behaviour."""

    def test_rejected_inputs(self):
        self.require_kcore()
        key = "a" * 2048
        self.assertIsNone(kcore.wots_address(key[:-1]))
        self.assertIsNone(kcore.wots_address("é" + key[1:]))
        self.assertIsNone(kcore.chains_hex(key, [-1] + [8] * 15))
        self.assertIsNone(kcore.chains_hex(key, [65] + [8] * 15))
        self.assertIsNone(kcore.chains_hex(key[:-1], [8] * 16))
        self.assertIsNone(kcore.mlkem1024_encaps(bytes(1000)))
        self.assertIsNone(kcore.mlkem768_encaps(bytes(1000)))
        self.assertIsNone(kcore.mlkem1024_decaps(bytes(1088), bytes(3168)))
        self.assertIsNone(kcore.mlkem768_decaps(bytes(1088), bytes(3168)))
        self.assertIsNone(kcore.mlkem1024_keypair(bytes(63)))

    def test_negative_step_count_keeps_pure_python_result(self):
        # A malformed molecular hash can drive a chain count below zero; the pure loop then takes
        # zero steps for that chain, and the kcore path must not change that.
        self.require_kcore()
        key = hashlib.shake_256(b"negative-count").hexdigest(1024)
        mol = MoleculeStructure()
        mol.normalized_hash = lambda: [9] + [0] * 63  # signing count 8 - 9 = -1 on chain 0
        self.assertEqual(self.pure(mol.signature_fragments, key, True), mol.signature_fragments(key, True))


class ModeTest(KcoreTestCase):
    def test_off_never_loads(self):
        os.environ["KNISHIO_KCORE"] = "off"
        self.assertFalse(kcore.available())
        self.assertIsNone(kcore.library_path())
        self.assertIsNone(kcore.wots_address("a" * 2048))

    def test_require_raises_when_the_library_is_missing(self):
        os.environ["KNISHIO_KCORE"] = "require"
        os.environ["KNISHIO_KCORE_LIB"] = str(Path(__file__).parent / "no-such-libkcore")
        with self.assertRaises(kcore.KcoreUnavailable):
            kcore.available()
        # Still raises on later calls: require mode never falls back silently.
        with self.assertRaises(kcore.KcoreUnavailable):
            kcore.wots_address("a" * 2048)

    def test_auto_falls_back_when_the_library_is_missing(self):
        os.environ["KNISHIO_KCORE"] = "auto"
        os.environ["KNISHIO_KCORE_LIB"] = str(Path(__file__).parent / "no-such-libkcore")
        self.assertFalse(kcore.available())

    def test_invalid_mode_is_rejected(self):
        os.environ["KNISHIO_KCORE"] = "bogus"
        with self.assertRaises(ValueError):
            kcore.available()


if __name__ == "__main__":
    unittest.main()
