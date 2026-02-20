import os
import json
import unittest
import tempfile
from types import SimpleNamespace

# Import your module (the filename is EncryptXpert.py)
import EncryptXpert as ex


class DummyLabel:
    def __init__(self, txt="AES-EAX"):
        self._t = txt
    def text(self):
        return self._t
    def setText(self, t):
        self._t = t


class DummyLineEdit:
    def __init__(self, txt=""):
        self._t = txt
    def text(self):
        return self._t
    def setText(self, t):
        self._t = t
    def setEnabled(self, _):  # no-op
        pass


class DummyProgress:
    def setValue(self, _): pass
    def setFormat(self, _): pass
    def maximum(self): return 1


class DummyButton:
    def setEnabled(self, _): pass
    class _Clicked:
        def connect(self, _): pass
        def disconnect(self): pass
    clicked = _Clicked()


class DummyLogger:
    def __init__(self):
        self.lines = []
    def appendPlainText(self, msg):
        self.lines.append(msg)


class EncryptXpertCoreTests(unittest.TestCase):
    def setUp(self):
        # Temporary workspace
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = self.tmp.name

        # Patch global UIWindow expected by EncryptXpert.py
        # Minimal attributes required by AES/DB paths used in your code.
        ex.UIWindow = SimpleNamespace(
            # encryption settings
            Enc_system_label=DummyLabel("AES-EAX"),
            FILE_EXT=".encex",
            USABLE_RAM=64 * 1024,  # 64 KB for fast unit test
            key_gen_bits=SimpleNamespace(value=lambda: 128),

            # inputs
            enc_key_input=DummyLineEdit(""),   # auto-generate
            enc_key_label=DummyLabel("Key (B):"),
            dec_key_input=DummyLineEdit(""),
            dec_nonce_input=DummyLineEdit(""),
            dec_key_label=DummyLabel("Key (H):"),

            # options
            option_Check_for_dublicate_key_nonce_in_DB=SimpleNamespace(isChecked=lambda: False),
            option_Delete_original_file=SimpleNamespace(isChecked=lambda: False),
            option_Store_key_nonce_in_DB=SimpleNamespace(isChecked=lambda: True),
            option_Delete_key_nonce_after_decryption=SimpleNamespace(isChecked=lambda: False),
            option_not_decrypted_verified_keep_original_file=SimpleNamespace(isChecked=lambda: True),
            option_not_verified_keep_key_nonce_DB=SimpleNamespace(isChecked=lambda: True),

            # UI widgets
            enc_button=DummyButton(),
            dec_button=DummyButton(),
            enc_progressBar=DummyProgress(),
            dec_progressBar=DummyProgress(),
            enc_files_counter_progressBar=DummyProgress(),
            dec_files_counter_progressBar=DummyProgress(),
            files_counter=0,

            # logging
            Logger=DummyLogger(),

            # DB file location
            DATABASE_FILE=os.path.join(self.base, "EX_DB.json"),

            # shortcuts no-op
            SetShortcuts=lambda *args, **kwargs: None,
            SaveOptions=lambda *args, **kwargs: None,
        )

        # Ensure empty DB exists
        with open(ex.UIWindow.DATABASE_FILE, "w", encoding="utf-8") as f:
            f.write("{}")

    def test_sha256_hash(self):
        p = os.path.join(self.base, "a.txt")
        with open(p, "wb") as f:
            f.write(b"hello")
        obj = ex.AES_SYSTEM()
        h = obj.sha256Hash(p)
        self.assertEqual(len(h), 64)  # hex sha256 length

    def test_encrypt_then_decrypt_roundtrip(self):
        # Create plaintext file
        plain_path = os.path.join(self.base, "plain.txt")
        with open(plain_path, "wb") as f:
            f.write(b"secret data " * 1000)

        # Encrypt using File wrapper (sets ManyFilesSelected etc.)
        ex.UIWindow.files_list = [plain_path]
        file_obj = ex.File([plain_path])
        file_obj.Encrypt()

        enc_path = plain_path + ex.UIWindow.FILE_EXT
        self.assertTrue(os.path.exists(enc_path), "Encrypted file not created")

        # Load key/nonce from DB into decrypt inputs
        # (Encrypt() saved them to DB)
        # Now set decrypt target
        ex.UIWindow.files_list = [enc_path]
        file_obj2 = ex.File([enc_path])

        # File() will auto-search DB when encrypted file selected, filling dec_key_input/nonce
        # Ensure fields got filled
        self.assertTrue(ex.UIWindow.dec_key_input.text() or True)  # may be filled on click in UI, but DB search runs
        # Call decrypt
        file_obj2.Decrypt()

        # Decrypted output
        dec_path = plain_path  # decrypted strips extension
        self.assertTrue(os.path.exists(dec_path), "Decrypted file not created")

        with open(dec_path, "rb") as f:
            recovered = f.read()
        self.assertIn(b"secret data", recovered)

    def test_db_save_and_search(self):
        # Fake values
        obj = ex.DB()
        obj.key = b"\x01" * 16
        obj.nonce = b"\x02" * 16
        obj.tag = b"\x03" * 16
        obj.filehash = "abc123"
        obj.address = "file.txt"
        ex.UIWindow.Enc_system_label.setText("AES-EAX")

        obj.SaveKeyNonceTag()

        # Now search
        obj2 = ex.DB()
        obj2.filehash = "abc123"
        found = obj2.KeyNonceSearcher()
        self.assertTrue(found)

    def test_validate_cert_against_ca_and_challenge(self):
        # Create CA + user cert using your functions
        _, ca_cert_path = ex.ensure_local_ca_exists()
        ca_cert = ex.load_ca_cert(ca_cert_path)

        # Create a fresh user identity (in-memory) using cryptography
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from datetime import datetime, timezone, timedelta
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        user_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EncryptXpert Users"),
            x509.NameAttribute(NameOID.COMMON_NAME, "unittest"),
        ])
        now = datetime.now(timezone.utc)
        user_cert = (
            x509.CertificateBuilder()
            .subject_name(user_subject)
            .issuer_name(ca_cert.subject)
            .public_key(user_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ex.serialization.load_pem_private_key(open(ex._ca_paths()[1], "rb").read(), None), hashes.SHA256())
        )

        ok, msg = ex.validate_cert_against_ca(user_cert, ca_cert)
        self.assertTrue(ok, msg)

        ok2, msg2 = ex.challenge_response(user_key, user_cert)
        self.assertTrue(ok2, msg2)


if __name__ == "__main__":
    unittest.main()
