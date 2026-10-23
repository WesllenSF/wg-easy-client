"""Testes do núcleo (rodam sem root, usando o MockBackend): python -m unittest discover tests"""
import io
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
import core  # noqa: E402

PEER_PUB = core.pubkey(core.genkey())


def conf(priv=None, allowed="0.0.0.0/0, ::/0", extra=""):
    return (f"[Interface]\nPrivateKey = {priv or core.genkey()}\nAddress = 10.8.0.2/32\nDNS = 192.0.2.53\n{extra}"
            f"\n[Peer]\nPublicKey = {PEER_PUB}\nAllowedIPs = {allowed}\nEndpoint = 203.0.113.10:51820\n")


class KeyTests(unittest.TestCase):
    def test_rfc7748_vector(self):
        priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        pub = core.x25519(priv, (9).to_bytes(32, "little"))
        self.assertEqual(pub.hex(), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

    def test_shared_secret_agrees(self):
        a, b = core.genkey(), core.genkey()
        sa = core.x25519(core.decode_key(a), core.decode_key(core.pubkey(b)))
        sb = core.x25519(core.decode_key(b), core.decode_key(core.pubkey(a)))
        self.assertEqual(sa, sb)


class ConfigTests(unittest.TestCase):
    def test_parse(self):
        info = core.parse_config(conf())
        self.assertEqual(info["addresses"], ["10.8.0.2/32"])
        self.assertEqual(info["dns"], ["192.0.2.53"])
        self.assertTrue(info["fullTunnel"])
        self.assertEqual(info["peers"][0]["publicKey"], PEER_PUB)

    def test_split_tunnel(self):
        self.assertFalse(core.parse_config(conf(allowed="10.0.0.0/8"))["fullTunnel"])

    def test_errors(self):
        for bad in ("", "[Peer]\nPublicKey = x\n", "[Interface]\nAddress = 1\n",
                    "[Interface]\nPrivateKey = abc\n", conf(extra="Foo = 1\n"),
                    conf(extra="ListenPort = abc\n")):
            with self.assertRaises(core.ConfigError, msg=bad):
                core.parse_config(bad)


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.m = core.Manager(self.tmp.name, core.MockBackend())

    def tearDown(self):
        self.tmp.cleanup()

    def test_only_one_active(self):
        self.m.create("vpn1", conf())
        self.m.create("vpn2", conf())
        self.m.activate("vpn1")
        self.assertEqual(self.m.active(), ["vpn1"])
        self.m.activate("vpn2")
        self.assertEqual(self.m.active(), ["vpn2"])
        self.assertEqual(self.m.settings["active"], "vpn2")
        self.m.deactivate("vpn2")
        self.assertEqual(self.m.active(), [])
        self.assertIsNone(self.m.settings["active"])

    def test_rename_active_keeps_running(self):
        self.m.create("vpn1", conf(), killswitch=True)
        self.m.activate("vpn1")
        self.m.update("vpn1", "casa", conf(), killswitch=True)
        self.assertEqual(self.m.active(), ["casa"])
        self.assertEqual(self.m.settings["active"], "casa")
        self.assertNotIn("vpn1", self.m.settings["killswitch"])

    def test_scripts_blocked(self):
        with self.assertRaises(core.ConfigError):
            self.m.create("x", conf(extra="PostUp = echo oi\n"))
        core.Manager(self.tmp.name, core.MockBackend(), allow_scripts=True).create("x", conf(extra="PostUp = echo oi\n"))

    def test_import_and_export(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("pasta/Escritório SP.conf", conf())
            z.writestr("leia.txt", "nada")
        r = self.m.import_files([("buf.zip", buf.getvalue()), ("vpn.conf", conf().encode()),
                                 ("vpn.conf", conf().encode()), ("ruim.conf", b"lixo")])
        self.assertEqual(r["imported"], ["Escrit_rio_SP", "vpn", "vpn-2"])
        self.assertEqual(len(r["errors"]), 1)
        with zipfile.ZipFile(io.BytesIO(self.m.export_zip())) as z:
            self.assertEqual(sorted(z.namelist()), ["Escrit_rio_SP.conf", "vpn-2.conf", "vpn.conf"])

    def test_detail_live(self):
        self.m.create("vpn1", conf())
        self.m.activate("vpn1")
        d = self.m.detail("vpn1")
        self.assertTrue(d["active"])
        self.assertIsNotNone(d["peers"][0]["rx"])

    def test_restore_after_restart(self):
        self.m.create("vpn1", conf())
        self.m.activate("vpn1")
        self.m.shutdown()
        m2 = core.Manager(self.tmp.name, core.MockBackend())
        m2.startup()
        self.assertEqual(m2.active(), ["vpn1"])


if __name__ == "__main__":
    unittest.main()
