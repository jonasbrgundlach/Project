from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import httplib
import ssl
import threading

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def handle_request(self, method):
        # Extract host and path from the request
        print("Received request")
        host = self.headers['Host']
        path = self.path
        headers = {key: value for key, value in self.headers.items()}
        
        # Create an HTTPS connection to the target server
        conn = None
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
            conn = httplib.HTTPSConnection(host, context=context, timeout=23)
        except Exception as e:
            self.send_error(500, "Failed to create HTTPS connection: {}".format(e))
            return
        
        # Read the request body if it is a POST request
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else None
        
        # Forward the request to the target server using HTTPS
        print("Attempting request")
        conn.request(method, path, body, headers)
        print("Request made. Method: {}, Body: {}, Headers: {}".format(method, body, headers))
        response = conn.getresponse()

        # Read the response from the target server
        response_body = response.read()
        self.send_response(response.status)
        for key, value in response.getheaders():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(response_body)
        
        conn.close()

def run_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, RequestHandler)
    print("HTTP server running on port {}".format(port))
    httpd.serve_forever()

def start_http_server():
    server_thread = threading.Thread(target=run_server, args=(8080,))
    server_thread.setDaemon(True)
    server_thread.start()