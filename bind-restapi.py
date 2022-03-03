"""
Author: Kyle Robertson
Contact: kyle.robertson@wei.com
Date: 9/8/2020
Description:
    This file defines code for a RESTful API server using the Tornado web framework that
    allows a user to create and delete A, PTR, and CNAME records within BIND DNS
    infrastructure by making HTTP(S) requests against this server. The server translates
    the parameters of the users request and uses nsupdate under the hood to make the
    actual DNS modifications. The server in it's entirety can by run with `python3 bind-restapi.py` 
"""

import json
import os
import sys
import shlex
import ssl
import logging
from tornado.ioloop import IOLoop
from tornado.web import url, RequestHandler, Application, Finish
from tornado.options import define, options, parse_command_line, parse_config_file
from tornado.httpserver import HTTPServer
from subprocess import Popen, PIPE, STDOUT
from tornado.log import LogFormatter

cwd = os.path.dirname(os.path.realpath(__file__))

# Defines CLI options for the entire module
define("address", default="0.0.0.0", type=str, help="Listen on interface")
define("port", default=9999, type=int, help="Listen on port")
define(
    "logfile", default=os.path.join(cwd, "bind-restapi.log"), type=str, help="Log file"
)
define("ttl", default="8640", type=int, help="Default TTL")
define("nameserver", default=["127.0.0.1"], type=list, help="List of DNS servers")
define(
    "sig_key",
    default=os.path.join(cwd, "dnssec_key.private"),
    type=str,
    help="DNSSEC Key",
)
define("secret", default="secret", type=str, help="Protection Header")
define("nsupdate_command", default="nsupdate", type=str, help="nsupdate")
define(
    "cert_path", default="/etc/ssl/certs/bind-api.pem", type=str, help="Path to cert"
)
define(
    "cert_key_path",
    default="/etc/ssl/private/bind-api-key.pem",
    type=str,
    help="Path to cert key",
)
define(
    "search_domain",
    default="mathworks.com",
    type=str,
    help="Domain in which to create search helper CNAME records. Don't include leading dot",
)

# Mandatory parameters that must be present in the incoming JSON body of create (POST)
# and delete (DELETE) requests
mandatory_create_parameters = ["ip", "hostname"]
mandatory_delete_parameters = ["ip", "hostname"]

# Templates for nsupdate scripts executed by the server. Parameters in curly brackets
# will be filled in when template is rendered
nsupdate_create_a = """\
server {0}
update add {1} {2} A {3}
send\n\
"""

nsupdate_create_ptr = """\
server {0}
update add {1} {2} PTR {3}
send\n\
"""

nsupdate_create_cname = """\
server {0}
update add {1} {2} CNAME {3}
send\n\
"""
nsupdate_delete_template = """\
server {0}
update delete {1} A {2}
send\n\
"""

nsupdate_delete_ptr = """\
server {0}
update delete {1} PTR {2}
send\n\
"""

nsupdate_delete_cname = """\
server {0}
update delete {1} CNAME {2}
send\n\
"""

app_log = logging.getLogger("tornado.application")


def auth(func):
    """
    Decorator to check headers for API key and authorize incoming requests. This should
    wrap all HTTP handler methods in the MainHandler class.
    """

    def header_check(self, *args, **kwargs):
        secret_header = self.request.headers.get("X-Api-Key", None)
        if not secret_header or not options.secret == secret_header:
            message='{"error": "X-Api-Key not correct"}'
            self.send_error(401, message=message)
            raise Finish()
        return func(self, *args, **kwargs)

    return header_check


def reverse_ip(ip):
    """
    Creates the reverse lookup record name given an IP address
    """
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


class JsonHandler(RequestHandler):
    """
    Request handler where requests and responses speak JSON.
    """

    def prepare(self):
        """
        Prepares incoming requests before they hit the request handling functions (get,
        put, post, delete, etc).

        Called immediately after initialize
        """
        # Incorporate request JSON into arguments dictionary.
        if self.request.body:
            try:
                json_data = json.loads(self.request.body)
                self.request.arguments.update(json_data)
            except ValueError:
                message = '{"error": "Unable to parse JSON."}'
                self.send_error(400, message=message)  # Bad Request
                raise Finish()

    def set_default_headers(self):
        self.set_header("Content-Type", "application/json")

    def write_error(self, status_code, **kwargs):
        """
        Convenience function for returning error responses to incoming requests 
        """

        if "message" in kwargs:
            reason = kwargs["message"]
            self.finish(json.dumps({"code": status_code, "message": reason}))


class ValidationMixin:
    """
    Simple mixin class that provides validation of request parameters
    """

    def validate_params(self, params):
        """
        Checks request for list of required parameters by name

        Parameters
        ----------

        params : list
            List of parameters that must be present in request.arguments

        Returns
        -------

        Sends error response if required parameter is not found
        """
        for parameter in params:
            if parameter not in self.request.arguments:
                message='{"error": "Parameter {0} not found"}'.format(parameter)
                self.send_error(400, message=message)
                raise Finish()


class MainHandler(ValidationMixin, JsonHandler):
    def _nsupdate(self, update):
        """
        Runs nsupdate command `update` in a subprocess
        """

        app_log.debug(f"nsupdate script: {update}")
        cmd = "{0} -k {1}".format(options.nsupdate_command, options.sig_key)
        app_log.debug(f"nsupdate cmd: {cmd}")
        print("CMD: {}".format(cmd))
        p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        print("Update type:")
        print(update)
        print(type(update))
        stdout = p.communicate(input=update.encode())[0]
        return p.returncode, stdout.decode()

    @auth
    def post(self):
        """
        Creates DNS records for authorized POST requests.
        """
        # Validate we have correct parameters in request body
        self.validate_params(mandatory_create_parameters)
        # Extract parameters
        ip = self.request.arguments["ip"]
        hostname = self.request.arguments["hostname"]
        ttl = options.ttl
        override_ttl = self.request.arguments.get("ttl")
        if override_ttl:
            ttl = int(override_ttl)
        # Loop through nameservers in config file
        error_msg = ""
        for nameserver in options.nameserver:
            update = nsupdate_create_a.format(nameserver, hostname, ttl, ip)
            # Create PTR records if asked
            if self.request.arguments.get("ptr") == "yes":
                reverse_name = reverse_ip(ip)
                ptr_update = nsupdate_create_ptr.format(nameserver, reverse_name, ttl, hostname)
                update += "\n" + ptr_update
            # Create search helper records if asked
            host, domain = hostname.split(".", 1)
            if (
                self.request.arguments.get("search_cname") == "yes"
                and domain != options.search_domain
            ):
                cname = host + "." + options.search_domain.strip(".")
                cname_update = nsupdate_create_cname.format(nameserver, cname, ttl, hostname)
                update += "\n" + cname_update

            return_code, stdout = self._nsupdate(update)
            if return_code != 0:
                msg = f"Unable to create record on nameserver {nameserver}.\nReturncode: {return_code}\nMsg: {stdout}"
                app_log.error(msg)
                error_msg += msg
            else:
                self.send_error(200, message="Record created")
                break
        else:
            msg = f"Unable to create record using any of the provided nameservers: {options.nameserver}"
            app_log.error(msg)
            app_log.error(error_msg)
            self.send_error(500, message=msg + error_msg)

    @auth
    def delete(self):
        self.validate_params(mandatory_delete_parameters)

        hostname = self.request.arguments["hostname"]
        ip = self.request.arguments["ip"]
        host, domain = hostname.split(".", 1)

        error_msg = ""
        for nameserver in options.nameserver:
            update = nsupdate_delete_template.format(nameserver, hostname, ip)
            if self.request.arguments.get("delete_ptr") == "yes":
                reverse_name = reverse_ip(ip)
                ptr_update = nsupdate_delete_ptr.format(nameserver, reverse_name, hostname)
                update += "\n" + ptr_update
            if self.request.arguments.get("delete_search_cname") == "yes":
                cname = host + "." + options.search_domain.strip(".")
                cname_update = nsupdate_delete_cname.format(nameserver, cname, hostname)
                update += "\n" + cname_update
            return_code, stdout = self._nsupdate(update)
            if return_code != 0:
                msg = f"Unable to update nameserver {nameserver}.\nReturncode: {return_code}\nMsg: {stdout}"
                app_log.error(msg)
                error_msg += msg
            else:
                self.send_error(200, message="Record deleted")
                break
        else:
            msg = f"Unable to delete record using any of the provided nameservers: {options.nameserver}"
            app_log.error(msg)
            app_log.error(error_msg)
            self.send_error(500, message=msg + error_msg)


class DNSApplication(Application):
    def __init__(self):
        # Sets up handler classes for each allowed route. 
        # Structure should be a list of url objects whose arguents are:
        # (regex for matching route, RequestHandler object, args for RequestHandler.initialize)
        handlers = [url(r"/dns", MainHandler)]
        Application.__init__(self, handlers)


def main():
    parse_config_file(cwd + "/bind-api.conf", final=False)
    parse_command_line(final=True)

    # Set up logging
    handler = logging.FileHandler(options.logfile)
    handler.setFormatter(LogFormatter())
    for logger_name in ("tornado.access", "tornado.application", "tornado.general"):
        logger = logging.getLogger(logger_name)
        logger.addHandler(handler)
        if options.logging is not None:
            logger.setLevel(getattr(logging, options.logging.upper()))
    # Set up Tornado application
    app = DNSApplication()
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(
        os.path.abspath(options.cert_path),
        keyfile=os.path.abspath(options.cert_key_path),
    )
    server = HTTPServer(app, ssl_options=ssl_ctx)
    server.listen(options.port, options.address)
    IOLoop.instance().start()

    # Run multiple instances of the application in multiple processes
    # app = DNSApplication()
    # server = tornado.httpserver.HTTPServer(app)
    # server.bind(8888)
    # server.start(0)  # forks one process per cpu
    # IOLoop.current().start()


if __name__ == "__main__":
    main()
