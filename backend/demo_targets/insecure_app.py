from http.server import BaseHTTPRequestHandler, HTTPServer


HTML = """
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Insecure Demo App</title>
  </head>
  <body>
    <h1>Demo Login</h1>
    <p>This intentionally insecure page is useful for validating the scanner.</p>
    <form method="post" action="/login">
      <label>Username <input type="text" name="username" /></label>
      <label>Password <input type="password" name="password" /></label>
      <button type="submit">Login</button>
    </form>
  </body>
</html>
""".strip()


class Handler(BaseHTTPRequestHandler):
    server_version = "InsecureDemo/1.0"

    def _send_html(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", self.server_version)
        self.send_header("X-Powered-By", "DemoPython")
        self.send_header("Set-Cookie", "sessionid=demo-session")
        self.end_headers()
        self.wfile.write(HTML.encode("utf-8"))

    def do_GET(self) -> None:  # noqa: N802
        self._send_html()

    def do_POST(self) -> None:  # noqa: N802
        self._send_html()

    def log_message(self, fmt: str, *args) -> None:
        print(fmt % args)


def main() -> None:
    server = HTTPServer(("127.0.0.1", 8081), Handler)
    print("Insecure demo target listening on http://127.0.0.1:8081")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
