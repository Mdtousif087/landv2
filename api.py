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
            # Call new API
            url = f"https://admin.gbssystems.com/public/storage/customer/28/vehicle/index.php?q={vehicle}"
            response = requests.get(url, timeout=10)
            
            # Parse the response
            data = response.json()
            
            # Extract mobile_no from the response
            mobile_no = None
            if data.get('rc_data') and data['rc_data'].get('data'):
                # Get the first item in data array (assuming there's at least one)
                vehicle_data = data['rc_data']['data'][0]
                mobile_no = vehicle_data.get('mobile_no')
            
            # Create simplified response
            simplified_response = {
                "mobile_no": mobile_no,
                "vehicle_number": vehicle
            }
            
            # Return simplified response
            self.wfile.write(json.dumps(simplified_response, indent=2).encode())
            
        except Exception as e:
            self.wfile.write(json.dumps({
                "error": str(e),
                "vehicle": vehicle
            }).encode())
