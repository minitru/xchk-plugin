"""Compaction screen 1.0.1: the Murtaza payloads inside a compaction summary are flagged lines. Copy into xchk-plugin/gate/tests/."""
import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import xchk_compact_screen as C
from test_labels_injection import MURTAZA


class CompactInjection(unittest.TestCase):
    def test_every_murtaza_payload_is_flagged(self):
        for pid, text in MURTAZA.items():
            fams = {h["family"] for h in C.screen("Summary of the session so far:\n" + text + "\nNext: continue.")}
            self.assertTrue(fams, pid)

    def test_encoded_text_names_the_decoded_line(self):
        hits = [h for h in C.screen(MURTAZA["JB-002"]) if h["family"] == "encoded-text"]
        self.assertEqual(len(hits), 1)
        self.assertIn("bananas", hits[0]["text"])

    def test_plain_summary_is_clean(self):
        self.assertEqual(C.screen("The user asked for a README; I drafted it and ran the tests, 12 passing."), [])

    def test_version(self):
        self.assertEqual(C.SCREEN_VERSION, "1.0.1")


if __name__ == "__main__":
    unittest.main()
