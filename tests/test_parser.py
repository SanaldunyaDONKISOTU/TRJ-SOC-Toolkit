import unittest

from main import analyze_lines, parse_line


class SSHLogAnalyzerTests(unittest.TestCase):
    def test_parse_failed_password(self):
        line = (
            "Nov 22 01:10:02 host sshd[1]: Failed password for root "
            "from 203.0.113.10 port 51001 ssh2"
        )
        event = parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.source_ip, "203.0.113.10")
        self.assertEqual(event.username, "root")

    def test_ignore_unrelated_line(self):
        self.assertIsNone(parse_line("Nov 22 01:10:02 host systemd[1]: Started service."))

    def test_threshold_detection(self):
        lines = [
            f"Nov 22 01:10:0{i} host sshd[1]: Failed password for root "
            f"from 203.0.113.10 port 5100{i} ssh2"
            for i in range(1, 6)
        ]
        attempts, findings = analyze_lines(lines, threshold=5)
        self.assertEqual(len(attempts), 5)
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].possible_brute_force)

    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):
            analyze_lines([], threshold=0)


if __name__ == "__main__":
    unittest.main()
