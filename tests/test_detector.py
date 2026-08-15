import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from detector.engine import DeauthDetector
from detector.events import WirelessEvent


class DetectorTests(unittest.TestCase):

    def test_empty_detector(self):
        result = DeauthDetector().evaluate()
        self.assertEqual(result.score, 0)
        self.assertEqual(result.severity, "NORMAL")

    def test_normal_low_rate(self):
        detector = DeauthDetector()
        now = datetime.now()

        for i in range(3):
            result = detector.add_event(
                WirelessEvent(
                    timestamp=now + timedelta(seconds=i * 3),
                    frame_type="deauthentication",
                    source="aa:aa:aa:aa:aa:aa",
                    destination=f"bb:bb:bb:bb:bb:{i:02x}",
                )
            )

        self.assertLess(result.score, 40)

    def test_broadcast_burst_is_high_risk(self):
        detector = DeauthDetector()
        now = datetime.now()

        for i in range(24):
            result = detector.add_event(
                WirelessEvent(
                    timestamp=now + timedelta(milliseconds=i * 100),
                    frame_type="deauthentication",
                    source="aa:aa:aa:aa:aa:aa",
                    destination="ff:ff:ff:ff:ff:ff",
                    reason_code=7,
                )
            )

        self.assertGreaterEqual(result.score, 60)
        self.assertIn(result.severity, {"HIGH", "CRITICAL"})

    def test_one_source_many_targets(self):
        detector = DeauthDetector()
        now = datetime.now()

        for i in range(10):
            result = detector.add_event(
                WirelessEvent(
                    timestamp=now + timedelta(milliseconds=i * 100),
                    frame_type="deauthentication",
                    source="aa:aa:aa:aa:aa:aa",
                    destination=f"02:00:00:00:00:{i:02x}",
                )
            )

        self.assertIn(
            "One transmitter is targeting many stations.",
            result.reasons,
        )

    def test_score_capped(self):
        detector = DeauthDetector()
        now = datetime.now()

        for i in range(100):
            result = detector.add_event(
                WirelessEvent(
                    timestamp=now,
                    frame_type="deauthentication",
                    source="aa:aa:aa:aa:aa:aa",
                    destination="ff:ff:ff:ff:ff:ff",
                )
            )

        self.assertLessEqual(result.score, 100)


if __name__ == "__main__":
    unittest.main()
