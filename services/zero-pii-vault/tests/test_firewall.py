import unittest
import json
import os
from fastapi.testclient import TestClient
from server import app

class TestFirewall(unittest.TestCase):
    def setUp(self):
        # Override config path or temporarily rewrite it to test specific IPs
        self.config_path = "config/firewall.json"
        
    def test_allow_all(self):
        # By default our config has "all"
        with TestClient(app, client=("192.168.1.100", 50000)) as client:
            response = client.get("/health")
            self.assertEqual(response.status_code, 200)

    def test_restricted_ip(self):
        # Temporarily rewrite config to restrict
        with open(self.config_path, "r") as f:
            original = f.read()
            
        try:
            restricted = [
                {"name": "internal", "subnet": "10.0.0.0/8"}
            ]
            with open(self.config_path, "w") as f:
                json.dump(restricted, f)
                
            # Need to re-init middleware or just create a new app instance?
            # Actually, modifying the file won't reload middleware unless we do it.
            # Let's instantiate middleware directly or just test the logic.
            from firewall import FirewallMiddleware
            mw = FirewallMiddleware(app, config_path=self.config_path)
            
            # Since TestClient doesn't easily let us swap middleware config post-init,
            # we check the middleware attributes directly.
            self.assertFalse(mw.allow_all)
            self.assertEqual(len(mw.allowed_networks), 1)
        finally:
            with open(self.config_path, "w") as f:
                f.write(original)

if __name__ == '__main__':
    unittest.main()
