import json
import os
import sys
import shlex
from tornado.ioloop import IOLoop
from tornado.web import url, RequestHandler, Application
from tornado.options import define, options, parse_command_line, parse_config_file
from subprocess import Popen, PIPE, STDOUT

# curl -X DELETE -H 'Content-Type: application/json' -H 'X-Api-Key: secret' -d '{ "hostname": "host.example.com"}' http://localhost:9999/dns
# curl -X POST -H 'Content-Type: application/json' -H 'X-Api-Key: secret' -d '{ "hostname": "host.example.com", "ip": "1.1.1.10" }' http://localhost:9999/dns
# curl -X POST -H 'Content-Type: application/json' -H 'X-Api-Key: secret' -d '{ "hostname": "host.example.com", "ip": "1.1.1.10", "ptr": "yes", "ttl": 86400}' http://localhost:9999/dns

cwd = os.path.dirname(os.path.realpath(__file__))

# Defines CLI options for the entire module
define('address', default='0.0.0.0', type=str, help='Listen on interface')
define('port', default=9999, type=int, help='Listen on port')
define('logfile', default=os.path.join(cwd, 'bind-restapi.log'), type=str, help='Log file')
define('ttl', default='8640', type=int, help='Default TTL')
define('nameserver', default='127.0.0.1', type=str, help='Master DNS')
define('sig_key', default=os.path.join(cwd, 'dnssec_key.private'), type=str, help='DNSSEC Key')
define('secret', default='secret', type=str, help='Protection Header')
define('nsupdate_command', default='nsupdate', type=str, help='nsupdate')

mandatory_create_parameters = ['ip', 'hostname']
mandatory_delete_parameters = ['hostname']

nsupdate_create_template = '''\
server {0}
update add {1} {2} A {3}
send\
'''
nsupdate_create_ptr = '''\
update add {0} {1} PTR {2}
send\
'''
nsupdate_delete_template = '''\
server {0}
update delete {1} A
send
update delete {1} PTR
send\
'''


def auth(func):
    """
    Decorator to check headers for API key and authorized incoming requests
    """
    def header_check(self, *args, **kwargs):
        secret_header = self.request.headers.get('X-Api-Key', None)
        if not secret_header or not options.secret == secret_header:
            self.send_error(401, message='X-Api-Key not correct')

        return func(self, *args, **kwargs)
    return header_check


def reverse_ip(ip):
    return '.'.join(reversed(ip.split('.'))) + ".in-addr.arpa"


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
                message = 'Unable to parse JSON.'
                self.send_error(400, message=message) # Bad Request

    def set_default_headers(self):
        self.set_header('Content-Type', 'application/json')

    def write_error(self, status_code, **kwargs):
        """
        Convenience function for returning error responses to incoming requests 
        """

        reason = self._reason
        if 'message' in kwargs:
            reason = kwargs['message']

        self.finish(json.dumps({'code': status_code, 'message': reason}))


class ValidationMixin():
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
                self.send_error(400, message='Parameter %s not found' % parameter)


class MainHandler(ValidationMixin, JsonHandler):

    def _nsupdate(self, update):
        """
        Runs nsupdate command `update` in a suprocess
        """
        #cmd = '{0} -k {1}'.format(options.nsupdate_command, options.sig_key)
        cmd = '{0}'.format(options.nsupdate_command)
        print("CMD: {}".format(cmd))
        p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, stderr=STDOUT)
        print("Update type:")
        print(type(update))
        stdout = p.communicate(input=update.encode())[0]
        return p.returncode, stdout.decode()

    @auth
    def post(self):
        self.validate_params(mandatory_create_parameters)

        ip = self.request.arguments['ip']
        hostname = self.request.arguments['hostname']

        ttl = options.ttl
        override_ttl = self.request.arguments.get('ttl')
        if override_ttl:
            ttl = int(override_ttl)

        update = nsupdate_create_template.format(
            options.nameserver,
            hostname,
            ttl,
            ip)

        if self.request.arguments.get('ptr') == 'yes':
            reverse_name = reverse_ip(ip)
            ptr_update = nsupdate_create_ptr.format(
                reverse_name,
                ttl,
                hostname)
            update += '\n' + ptr_update

        print("Update string:")
        print(update)
        return_code, stdout = self._nsupdate(update)
        if return_code != 0:
            self.send_error(500, message=stdout)
        self.send_error(200, message='Record created')

    @auth
    def delete(self):
        self.validate_params(mandatory_delete_parameters)

        hostname = self.request.arguments['hostname']

        update = nsupdate_delete_template.format(
            options.nameserver,
            hostname)
        return_code, stdout = self._nsupdate(update)
        if return_code != 0:
            self.send_error(500, message=stdout)
        self.send_error(200, message='Record deleted')


class DNSApplication(Application):
    def __init__(self):
        # (regex for matching route, RequestHandler object, args for RequestHandler.initialize)
        handlers = [
            url(r"/dns", MainHandler)
        ]
        Application.__init__(self, handlers)


def main():
    parse_config_file("/etc/bind-api.conf")
    print(options.as_dict())
    parse_command_line() 
    print(options.as_dict())
    app = DNSApplication()
    app.listen(options.port, options.address)
    IOLoop.instance().start()

    # Multiple processes
    # app = DNSApplication()
    # server = tornado.httpserver.HTTPServer(app)
    # server.bind(8888)
    # server.start(0)  # forks one process per cpu
    # IOLoop.current().start()

if __name__ == '__main__':
    main()
