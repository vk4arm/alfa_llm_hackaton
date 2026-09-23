with open('src/server.py', 'r') as f:
    content = f.read()

import_firewall = "from firewall import FirewallMiddleware\n"
if "from firewall import FirewallMiddleware" not in content:
    content = content.replace('from fastapi.middleware.cors import CORSMiddleware', 'from fastapi.middleware.cors import CORSMiddleware\nfrom firewall import FirewallMiddleware')

middleware_code = """app.add_middleware(FirewallMiddleware, config_path="config/firewall.json")
app.add_middleware(
    CORSMiddleware,"""

content = content.replace('app.add_middleware(\n    CORSMiddleware,', middleware_code)

with open('src/server.py', 'w') as f:
    f.write(content)
