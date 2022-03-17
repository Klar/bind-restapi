"""
Author: klar
Contact: https://github.com/klar
Date: 03/10/2022
Description:
    Changed restapi URL to use another format (for keyvault-acmebot).
    Only able to create and delete TXT records. Able to 'GET' the full zone
    from the nameserver via 'named-checkconf' command.

Author: Kyle Robertson
Contact: kyle.robertson@wei.com
Date: 9/8/2020
Description:
    This file defines code for a RESTful API server using the Tornado web
    framework that allows a user to create and delete A, PTR, and CNAME records
    within BIND DNS infrastructure by making HTTP(S) requests against this
    server. The server translates the parameters of the users request and uses
    nsupdate under the hood to make the actual DNS modifications.
    The server in it's entirety can by run with `python3 bind-restapi.py`
"""

import json
import os
import shlex
import ssl
import logging
import re
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
define("ttl", default="60", type=int, help="Default TTL")
define("nameserver", default=["127.0.0.1"],
       type=list, help="List of DNS servers")
define("get_nameservers", default=[],
       type=list, help="Hardcoded nameservers for zone, not using dig (faster).")
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

# Mandatory parameters that must be present in the incoming JSON body
# of create (POST)and delete (DELETE) requests
mandatory_create_parameters = ["type", "ttl", "values"]

# Templates for nsupdate scripts executed by the server.
# Parameters in curly brackets will be filled in when template is rendered

nsupdate_create_txt = """\
server {0}
update add {1} {2} TXT {3}
send\n\
"""

nsupdate_delete_txt = """\
server {0}
update delete {1} TXT
send\n\
"""

app_log = logging.getLogger("tornado.application")


def auth(func):
    """
    Decorator to check headers for API key and authorize incoming requests.
    This should wrap all HTTP handler methods in the MainHandler class.
    """

    def header_check(self, *args, **kwargs):
        secret_header = self.request.headers.get("X-Api-Key", None)
        if not secret_header or not options.secret == secret_header:
            message = '{"error": "X-Api-Key not correct"}'
            self.send_error(401, message=message)
            raise Finish()
        return func(self, *args, **kwargs)

    return header_check


def splitUrl(path):
    """
    Split the url / path we receive, return the values.
    """
    # split parameters
    path = path.split("/")
    zoneId = path[0]
    records = path[1]
    recordName = path[2]

    return zoneId, records, recordName


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
                self.send_error(
                    400, message="Parameter %s not found" % parameter)
                raise Finish()

    def validate_path(self, path):
        zoneId, records, recordName = splitUrl(path)

        # check if url / sub-domain is in correct format.
        isDomain = re.compile(
            "([a-z0-9A-Z]\.)*[a-z0-9-]+\.([a-z0-9]{2,24})+(\.co\.([a-z0-9]{2,24})|\.([a-z0-9]{2,24}))*"
        )
        if not records == "records" or not isDomain.match(zoneId):
            self.send_error(400, message="URL is not in correct format.")
            raise Finish()

        return zoneId, records, recordName


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
        # print(update)
        # print(type(update))
        # print(update.encode())
        stdout = p.communicate(input=update.encode())[0]
        return p.returncode, stdout.decode()

    def _getZones(self):
        """
        Runs 'named-checkconf -l' command in a subprocess.
        """

        cmd = "named-checkconf -l"
        # print("CMD: {}".format(cmd))
        p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        stdout = p.communicate(input=cmd.encode())[0]
        return p.returncode, stdout.decode()

    def _getNameservers(self, zoneId):
        """
        Runs 'dig' command in a subprocess to get nameservers.
        """

        cmd = "dig NS " + zoneId + " @localhost +short"
        # print("CMD: {}".format(cmd))
        p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        stdout = p.communicate(input=cmd.encode())[0]
        return p.returncode, stdout.decode()

    @auth
    def get(self):
        """
        get DNS zones for authorized GET requests.
        """

        return_code, zones = self._getZones()
        zoneReply = list()
        for zone in zones.splitlines():
            zone_split = zone.split(" ")
            if zone_split[0].find(".arpa") == -1 and zone_split[0].find("localhost") == -1 and zone_split[0] != ".":
                zoneDict = dict()
                zoneDict["id"] = zone_split[0]
                zoneDict["name"] = zone_split[0]

                # hardcoded nameservers, no need to use (slow) dig for get return.
                if options.get_nameservers:
                    zoneDict["nameServers"] = options.get_nameservers
                else:
                    return_code, nameServers = self._getNameservers(
                        zone_split[0])
                    if return_code != 0:
                        msg = f"Unable to get zones: {zone_split[0]} nameserver(s).\n"
                        app_log.error(msg)
                    else:
                        nameServers = nameServers.splitlines()
                        zoneDict["nameServers"] = nameServers

                zoneReply.append(zoneDict)

        # print(zoneReply)
        self.send_error(200, message=zoneReply)

    @auth
    def post(self, path):
        """
        Creates DNS records for authorized POST requests.
        """

        # Validate we have correct parameters in request body
        self.validate_params(mandatory_create_parameters)

        # Validate that path is correct
        zoneId, records, recordName = self.validate_path(path)

        # Extract parameters
        type = self.request.arguments["type"]
        if type != "TXT":
            self.send_error(
                400, message="We only allow TXT updates.")
            raise Finish()

        ttl = options.ttl
        override_ttl = self.request.arguments.get("ttl")
        if override_ttl:
            ttl = int(override_ttl)
        values = self.request.arguments["values"]

        # Loop through nameservers in config file
        error_msg = ""
        update = ""
        for nameserver in options.nameserver:
            for value in values:
                update += nsupdate_create_txt.format(
                    nameserver, recordName + "." + zoneId, ttl, value)

            return_code, stdout = self._nsupdate(update)
            if return_code != 0:
                msg = f"Unable to create record on nameserver {nameserver}."
                app_log.error(stdout)
                self.send_error(500, message=msg)
            else:
                self.send_error(200, message="Record created")
                break

    @auth
    def delete(self, path):
        """
        deletes DNS txt record for authorized DELETE requests.
        """

        # Validate that path is correct
        zoneId, records, recordName = self.validate_path(path)

        error_msg = ""
        for nameserver in options.nameserver:
            update = nsupdate_delete_txt.format(
                nameserver, recordName + "." + zoneId, )
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
        # (regex for matching route, RequestHandler object,
        # args for RequestHandler.initialize)
        handlers = [
            url(r"/zones/(.*?)/?", MainHandler),
            url(r"/zones/?", MainHandler)
        ]

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


if __name__ == "__main__":
    main()
