import SimpleHTTPServer
import SocketServer
import threading 
import os

PORT = 8000
HTML_FILE = "index.html"

class MyHttpRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            script_dir = os.path.dirname(__file__)
            file_path = os.path.join(script_dir, HTML_FILE)
            with open(file_path, 'r') as file:
                html_content = file.read()
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(html_content)
        except Exception as e:
            print("[Err]: {} ".format(e) )
            self.send_response(500)
            self.end_headers()
            self.wfile.write("[Err] Internal Server Error")

class CustomTCPServer(SocketServer.TCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass):
        SocketServer.TCPServer.__init__(self, server_address, RequestHandlerClass)
        self._is_running = True

    def serve_until_stopped(self):
        while self._is_running:
            self.handle_request()

    def stop(self):
        self._is_running = False
    
def run_server():
    handler = MyHttpRequestHandler
    server = CustomTCPServer(("", PORT), handler)

    server_thread = threading.Thread(target=server.serve_until_stopped)
    server_thread.isDaemon = True
    server_thread.start()

    return server, server_thread

