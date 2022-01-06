"""
HTTP Reverse-Proxy for Docker Socket, Exposing Only Endpoints Required by Traefik
Copyright (C) 2021 Fabian Peter Hammerle <fabian.github@hammerle.me>

Tested in docker.io/python:3.9.4-alpine image with Traefik v2.5.6 and Docker v20.10.7.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3
as published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import functools
import http.client
import http.server
import json
import logging
import pathlib
import re
import socket
import socketserver
import typing

_LOGGER = logging.getLogger(__name__)


class _HttpConnectionUnixSocket(http.client.HTTPConnection):
    def __init__(self, path: pathlib.Path) -> None:
        self._path = path
        super().__init__(host="0.0.0.0")

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self._path.as_posix())


class _HTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def __init__(  # pylint: disable=too-many-arguments
        self,
        request: socket.socket,
        client_address: typing.Tuple[str, int],
        server: http.server.HTTPServer,
        unprotected_socket_path: pathlib.Path,
        client_ip_address_allowlist: typing.Set[str],
    ) -> None:
        self._unprotected_socket_path = unprotected_socket_path
        self._client_ip_address_allowlist = client_ip_address_allowlist
        super().__init__(request=request, client_address=client_address, server=server)

    def _request(self) -> http.client.HTTPResponse:
        connection = _HttpConnectionUnixSocket(self._unprotected_socket_path)
        connection.request(method=self.command, url=self.path)
        return connection.getresponse()

    def _request_json(
        self,
    ) -> typing.Tuple[int, typing.Dict[str, str], typing.Union[dict, list]]:
        response = self._request()
        return response.status, dict(response.getheaders()), json.load(response)

    def _respond_json(
        self, *, status_code: int, headers: typing.Dict[str, str], data: object
    ) -> None:
        self.send_response(code=status_code)
        body = json.dumps(data).encode("ascii")
        headers["Content-Length"] = str(len(body))
        for keyword, value in headers.items():
            if keyword != "Transfer-Encoding":
                self.send_header(keyword=keyword, value=value)
        self.end_headers()
        self.wfile.write(body)

    def _verify_client_allowed(self) -> bool:
        # `.send_error` fails in overwritten `.handle_one_request`
        if self.client_address[0] not in self._client_ip_address_allowlist:
            self.send_error(code=403, message="IP Address Blocked")
            return False
        return True

    def do_HEAD(self) -> None:  # pylint: disable=invalid-name
        if not self._verify_client_allowed():
            return
        if self.path != "/_ping":
            self.send_error(code=403)
        else:
            self.send_response(code=self._request().status)
            self.end_headers()

    def do_GET(self) -> None:  # pylint: disable=invalid-name
        if not self._verify_client_allowed():
            return
        if re.match(
            r"^/v1\.\d+/containers/json(\?limit=0)?$", self.path
        ):  # includes get params
            status_code, headers, data = self._request_json()
            self._respond_json(
                status_code=status_code,
                headers=headers,
                data=[{"Id": c["Id"]} for c in data],
            )
        elif re.match(r"^/v1\.\d+/containers/[0-9a-f]+/json$", self.path):
            status_code, headers, data = self._request_json()
            assert isinstance(data, dict)
            self._respond_json(
                status_code=status_code,
                headers=headers,
                data={
                    "Id": data["Id"],
                    "State": {"Running": data["State"]["Running"]},
                    "Name": "filtered-" + data["Id"],
                    "Config": {
                        "Labels": {
                            k: v
                            for k, v in data["Config"]["Labels"].items()
                            if k.startswith("traefik.")
                        },
                    },
                    "NetworkSettings": {
                        "Networks": {  # true name for label `traefik.docker.network`
                            name: {"IPAddress": n["IPAddress"]}
                            for name, n in data["NetworkSettings"]["Networks"].items()
                        }
                    },
                },
            )
        elif re.match(r"^/v1\.\d+/version$", self.path):
            status_code, headers, data = self._request_json()
            assert isinstance(data, dict)
            self._respond_json(
                status_code=status_code,
                headers=headers,
                data={},  # apparently, traefik always uses api v1.24
            )
        elif re.match(
            r"^/v1\.\d+/events\?filters=%7B%22type%22%3A%7B%22container%22%3Atrue%7D%7D$",
            self.path,
        ):
            response = self._request()
            headers = dict(response.getheaders())
            assert headers["Transfer-Encoding"] == "chunked"
            self.send_response(code=response.status)
            for keyword, value in response.getheaders():
                self.send_header(keyword=keyword, value=value)
            self.end_headers()
            while chunk_bytes := response.readline():
                chunk_data = json.loads(chunk_bytes)
                if chunk_data["Type"] == "container" and chunk_data["Action"] in {
                    "start",
                    "die",
                }:
                    # apparently, traefik ignores Actor.ID & always re-fetches all containers' data
                    chunk_bytes_filtered = json.dumps(
                        {"Action": str(chunk_data["Action"])}
                    ).encode("ascii")
                    self.wfile.write(f"{len(chunk_bytes_filtered):x}\r\n".encode())
                    self.wfile.write(chunk_bytes_filtered)
                    self.wfile.write(b"\r\n")
        else:
            self.send_error(code=403)

    def log_request(self, code="-", size="-") -> None:
        if code != 200:
            super().log_request(code=code, size=size)


class _ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    pass


def _main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        "--unprotected-socket-path",
        type=pathlib.Path,
        default=pathlib.Path("/var/run/docker.sock"),
        help="default: %(default)s",
    )
    argparser.add_argument(
        "--protected-port", type=int, default=2375, help="default: %(default)u"
    )
    # cave: `docker network create --internal` does not disconnect the default network namespace!
    # thus a allowlist is required to keep processes in the default network namespace
    # (e.g. interactive users, containers with `--network host`) from using the docker socket.
    argparser.add_argument(
        "--client-ip-address-allowlist",
        type=str,
        nargs="+",
        required=True,
    )
    args = argparser.parse_args()
    with _ThreadedHTTPServer(
        server_address=("", args.protected_port),
        RequestHandlerClass=functools.partial(
            _HTTPRequestHandler,
            unprotected_socket_path=args.unprotected_socket_path,
            client_ip_address_allowlist=set(args.client_ip_address_allowlist),
        ),
    ) as http_server:
        _LOGGER.info("listening on %s:%d", *http_server.server_address)
        http_server.serve_forever()


if __name__ == "__main__":
    _main()
