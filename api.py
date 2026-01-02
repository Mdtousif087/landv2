from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import requests

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Get vehicle from query
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        vehicle = params.get('vehicle', [''])[0].strip().upper()
        
        # Headers
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        if not vehicle:
            self.wfile.write(json.dumps({
                "error": "Add ?vehicle=XXXX parameter"
            }).encode())
            return
        
        try:
            # Call your API
            url = f"http://195.114.193.191:5019/{vehicle}"
            response = requests.get(url, timeout=10)
            
            # Return same response
            self.wfile.write(response.content)
            
        except Exception as e:
            self.wfile.write(json.dumps({
                "error": str(e),
                "vehicle": vehicle
            }).encode())