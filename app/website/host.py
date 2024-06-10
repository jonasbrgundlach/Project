import SimpleHTTPServer
import SocketServer

PORT = 8000
HTML_FILE = '/index.html'

class MyHttpRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        try:
            with open(HTML_FILE, 'r') as file:
                html_content = file.read()
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(html_content)
        except Exception as e:
            print("Error: {}".format(e))
            self.send_response(500)
            self.end_headers()
            self.wfile.write("Internal Server Error")

def run():
    running = True
    handler = MyHttpRequestHandler
    httpd = SocketServer.TCPServer(("", PORT), handler)
    print ("Serving at port {}".format(PORT))
    while(running):
        httpd.handle_request()
    
    def stop():
        running = False
        httpd.server_close()