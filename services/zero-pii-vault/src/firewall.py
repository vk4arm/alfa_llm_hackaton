import json
import ipaddress
import os
from typing import List, Dict, Any
from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

class FirewallMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, config_path: str = "config/firewall.json"):
        super().__init__(app)
        self.config_path = config_path
        self.allow_all = False
        self.allowed_networks = []
        self._load_config()

    def _load_config(self):
        if not os.path.exists(self.config_path):
            # If no config, default to deny all (secure by default)
            print(f"Firewall config {self.config_path} not found. Denying all traffic.")
            return

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                rules = json.load(f)
            
            for rule in rules:
                subnet = rule.get("subnet", "").strip().lower()
                if subnet == "all" or subnet == "0.0.0.0/0":
                    self.allow_all = True
                    break
                try:
                    # Support both single IP and CIDR notation
                    if "/" not in subnet:
                        subnet = f"{subnet}/32"
                    network = ipaddress.ip_network(subnet, strict=False)
                    self.allowed_networks.append((rule.get("name", "unknown"), network))
                except ValueError as e:
                    print(f"Firewall config error: invalid subnet '{subnet}' - {e}")
        except Exception as e:
            print(f"Failed to load firewall config: {e}")

    async def dispatch(self, request: Request, call_next):
        if self.allow_all:
            return await call_next(request)
            
        client_ip = request.client.host if request.client else None
        if not client_ip:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Access forbidden: Client IP could not be determined"}
            )
            
        try:
            ip_obj = ipaddress.ip_address(client_ip)
            is_allowed = False
            for name, network in self.allowed_networks:
                if ip_obj in network:
                    is_allowed = True
                    break
                    
            if not is_allowed:
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": f"Access forbidden: IP {client_ip} is not in allowed subnets"}
                )
                
        except ValueError:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": f"Access forbidden: Invalid client IP format"}
            )

        return await call_next(request)
