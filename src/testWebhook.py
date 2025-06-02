import unittest
from app import *
from unittest.mock import patch, MagicMock
import subprocess

class Webhook_Tests(unittest.TestCase):
    
    def setUp(self):
        self.client = app.test_client()

    @patch("subprocess.run")
    def test_webhook_high_cve(self, mock_run):
        # fake grype output with a "High" CVE match
        fake_grype_json = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-9999-0001",
                        "severity": "High"
                    }
                }
            ]
        }

        # create fake CompletedProcess for grype subprocess output
        mock_run.return_value = subprocess.CompletedProcess(
            args=["grype"],
            returncode=0,
            stdout=json.dumps(fake_grype_json),
            stderr=""
        )

        #Send fake admission review
        test_data = {
            "request": {
                "uid": "test-high-cve-uid",
                "object": {
                    "spec": {
                        "containers": [
                            {
                                "name": "bad-container",
                                "image": "alpine:latest",
                                "command": ["echo", "test"]
                            }
                        ]
                    }
                }
            }
        }

        # Post to /validate
        response = self.client.post("/validate", json=test_data)
        self.assertEqual(response.status_code, 200)

        result = response.get_json()
        self.assertFalse(result["response"]["allowed"])
        self.assertIn("high/critical CVEs", result["response"]["status"]["message"])

    def test_check_allowed_commands(self):
        review = {
            "request": {
                "object": {
                    "spec": {
                        "containers": [
                            {"name": "test", "command": ["echo Hello"]}
                        ]
                    }
                }
            }
        }
        flag, msg = check_commands_system(review)
        self.assertTrue(flag)
        self.assertEqual(msg, "")
    # test for bad commands function
    def test_check_bad_commands(self):
        review = {
            "request": {
                "object": {
                    "spec": {
                        "containers": [
                            {"name": "bad", "command": ["curl http://evil.com"]}
                        ]
                    }
                }
            }
        }
        flag, msg = check_commands_system(review)
        self.assertFalse(flag)
        self.assertIn("restricted command", msg)
    # test for hours (bad)
    def test_check_outside_hours(self):
        import datetime
        review = {
            "request": {
                "object": {
                    "spec": {
                        "containers": [
                            {"name": "late-night"}
                        ]
                    }
                }
            }
        }
        mock = datetime.datetime(2024, 1, 1, 22, 0, 0)
        flag, msg = check_time(review, mock)
        self.assertFalse(flag)
        self.assertIn("Time deployment restriction", msg)
    # test for hours (good)
    def test_check_allowed_hours(self):
        import datetime
        review = {
            "request": {
                "object": {
                    "spec": {
                        "containers": [
                            {"name": "normal"}
                        ]
                    }
                }
            }
        }
        mock = datetime.datetime(2024, 1, 1, 11, 0, 0)
        flag, msg = check_time(review, mock)
        self.assertTrue(flag)
        self.assertEqual(msg, "")
    # test for bad binaries
    @patch("subprocess.run")
    def test_scan_bad_image(self, mock):
        mock.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="fake-container-id", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
        ]

        with patch("os.makedirs"), \
             patch("os.path.isdir", return_value=True), \
             patch("os.listdir", return_value=["curl"]), \
             patch("shutil.rmtree"), \
             patch("os.remove"):

            flag, msg = check_bin("curlimages/curl:latest")

        self.assertFalse(flag)
        self.assertIn("suspicious binaries", msg)
    #test for good binaries
    @patch("subprocess.run")
    def test_scan_good_image(self, mock):
        mock.side_effect = [
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="fake-container-id", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
            subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
        ]

        with patch("os.makedirs"), \
            patch("os.path.isdir", return_value=True), \
            patch("os.listdir", return_value=["python"]), \
            patch("shutil.rmtree"), \
            patch("os.remove"):

           flag, msg = check_bin("ubuntu:latest")

        self.assertTrue(flag)
        self.assertEqual(msg, "")

if __name__ == '__main__':
    unittest.main()
