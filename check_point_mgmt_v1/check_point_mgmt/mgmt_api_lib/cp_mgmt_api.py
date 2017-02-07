#
# cp_management_api.py
# version 1.0
#
# A library for communicating with Check Point's management server using python 2.X
# written by: Check Point software technologies inc. 
# December 2015
# tested with Check Point R80 (tested with take hero2 198)
#


# api response structure 
from api_response import APIResponse

import httplib
import hashlib
import ssl
import json
import os.path
import time
import base64
import socket

#
#
# APIClient encapsulates everything that the user needs to do for communicating with a Check Point management server
#
#


class APIClientArgs:
    #CHANGED
    def __init__(self, port=443, fingerprint=None, sid=None, server=None, http_debug_level=0, api_calls=None, debug_file="", proxy_host=None, proxy_port=8080, proxy_protocol="http"):
        self.port = port                                    # port on management server
        self.fingerprint = fingerprint                      # management server fingerprint
        self.sid = sid                                      # session-id.
        self.server = server                                # management server name or IP-address
        self.http_debug_level = http_debug_level            # debug level
        self.api_calls = api_calls if api_calls else []     # an array with all the api calls (for debug purposes)
        self.debug_file = debug_file                        # name of debug file. If left empty, debug data will not be saved to disk.
        self.proxy_host = proxy_host                        # HTTP proxy server address
        self.proxy_port = proxy_port                        # HTTP proxy port
        self.proxy_protocol = proxy_protocol                # currently only http and https are supported


class APIClient:

    #
    # initialize class
    #
    '''def __init__(self):
        self.port                   = APIClientArgs.port                                # port on management server
        self.fingerprint            = APIClientArgs.fingerprint                         # management server fingerprint
        self.sid                    = APIClientArgs.sid                                 # session-id.
        self.server                 = APIClientArgs.server                              # management server name or IP-address
        self.http_debug_level       = APIClientArgs.http_debug_level                    # debug level
        self.api_calls              = APIClientArgs.api_calls                           # an array with all the api calls (for debug purposes)
        self.debug_file             = APIClientArgs.debug_file                          # name of debug file. If left empty, debug data will not be saved to disk.
        self.proxy_host             = APIClientArgs.proxy_host                          # HTTP proxy server address
        self.proxy_port             = APIClientArgs.proxy_port                          # HTTP proxy port
        self.proxy_protocol = "http"        # currently only http and https are supported
'''
    def __init__(self, api_client_args):
        self.port                   = api_client_args.port                  # port on management server
        self.fingerprint            = api_client_args.fingerprint           # management server fingerprint
        self.sid                    = api_client_args.sid                   # session-id.
        self.server                 = api_client_args.server                # management server name or IP-address
        self.http_debug_level       = api_client_args.http_debug_level      # debug level
        self.api_calls              = api_client_args.api_calls             # an array with all the api calls (for debug purposes)
        self.debug_file             = api_client_args.debug_file            # name of debug file. If left empty, debug data will not be saved to disk.
        self.proxy_host             = api_client_args.proxy_host            # HTTP proxy server address
        self.proxy_port             = api_client_args.proxy_port            # HTTP proxy port
        self.proxy_protocol         = api_client_args.proxy_protocol        # currently only http and https are supported


    def __enter__(self):
        return self
    #
    # destructor
    #

    def __exit__(self, exc_type, exc_value, traceback):

        # if sid is not empty (the login api was called), then call logout
        if self.sid:
            self.api_call("logout")

        # save debug data with api calls to disk
        if self.debug_file!="":
            print "\nSaving data to debug file {}\n".format(self.debug_file)
            out_file = open(self.debug_file, 'w+')
            out_file.write(json.dumps(self.api_calls, indent=4, sort_keys=True))
   
    #
    # login
    # ----------------------------------------------------
    # performs a 'login' API call to the management server
    #
    # arguments:
    #    server    - the IP address or name of the Check Point managemenet server
    #    user      - Check Point admin name
    #    password  - Check Point admin password
    #    continue-last-session - [optional] it is possible to conitue the last Check Point session or to create a new one 
    #
    # return: apiresponse object
    # side-effects: updates the class's uid and server variables
    #
    #
    def login(self, server, user, password, domain=None, continue_last_session=False, proxy_host=None, proxy_port=None, proxy_protocol=None):
        if proxy_host and proxy_port and (proxy_protocol == "http" or proxy_protocol == "https"):
            self.proxy_host = proxy_host
            self.proxy_port = proxy_port
            self.proxy_protocol = proxy_protocol
        credentials = {"user": user, "password": password, "continue-last-session": continue_last_session}
        if domain:
            credentials["domain"] = domain
        login_res = self.api_call("login", credentials, server)
        if login_res.success:
            self.sid = login_res.data["sid"]
            self.server = server
        return login_res

    #
    # gen_api_query
    # ----------------------------------------------------
    # The APIs that return a list of objects are limited by the number of objects that they return.
    # To get the full list of objects, there's a need to make repeated API calls each time using a different offset
    # until all the objects are returned.
    # This API makes such repeated API calls and after each call, returns an APIResponse object.
    # The APIResponse objects's .data member is a dict: { "objects": [...], "from": x, "to": y, "total": z }
    # You can use this information to show progress (i.e. "Received y/z objects." messages) by iterating over the function.
    #
    #
    #
    # arguments:
    #    command        - name of API command. This command should be an API that returns an array of objects (for example: show-hosts, show networks, ...)
    #    details-level  - query APIs always take a details-level argument. possible values are "standard", "full", "uid"
    #    container_key  - the field in the .data dict that contains the objects
    # return: an APIResponse object as detailed above
    #
    def gen_api_query(self, command, details_level="standard", container_keys=["objects"], payload={}):
        limit = 50  # each time get no more than 50 objects
        finished = False  # will become true after getting all the data
        errors_found = False  # will become true in case we get an error
        all_objects = {}  # accumulate all the objects from all the API calls
        for key in container_keys:
            all_objects[key] = []
        iterations = 0  # number of times we've made an API call
        api_res = {}  # API call response object

        # are we done?
        while not finished:
            # make the API call, offset should be increased by 'limit' with each iteration
            payload.update({"limit": limit, "offset": iterations * limit, "details-level": details_level})
            api_res = self.api_call(command, payload)
            iterations += 1
            if api_res.success is True:
                total_objects = api_res.data["total"]  # total number of objects
                received_objects = api_res.data["to"]  # number of objects we got so far
                for key in container_keys:
                    all_objects[key] += api_res.data[key]
                    api_res.data[key] = all_objects[key]
                # did we get all the objects that we're supposed to get
                if received_objects == total_objects:
                    finished = True
            yield api_res

    #
    # api_call
    # ----------------------------------------------------
    # performs a web-service API request to the management server
    #
    # arguments:
    #    command       - the command is placed in the URL field
    #    payload       - a JSON object (or a string representing a JSON object) with the command arguments
    #    server        - [optional]. The Check Point management server. when omitted use self.server.
    #    sid           - [optional]. The Check Point session-id. when omitted use self.sid.
    #    wait_for_task - dertermines the behavior when the API server responds with a "task-id".
    #                    by default, the function will periodically check the status of the task
    #                    and will not return until the task is completed.
    #                    when wait_for_task=False, it is up to the user to call the "show-task" API and check
    #                    the status of the command.
    #
    # return: APIResponse object
    # side-effects: updates the class's uid and server variables
    #
    #
    def api_call(self, command, payload=None, server=None, sid=None, wait_for_task=True):
        if payload is None:
            payload = {}
        # convert the json payload to a string if needed
        if isinstance(payload, str):
            _data = payload
        else:
            _data = json.dumps(payload, sort_keys=False)

        # update class members if needed.
        if server is None:
            server = self.server
        if sid is None:
            sid = self.sid

        # set headers
        _headers = {"User-Agent": "python-api-wrapper", "Accept": "*/*",
                    "Content-Type": "application/json", "Content-Length": len(_data)}
        
        # in all API calls (except for 'login') a header containing the Check Point session-id is required.
        if sid is not None:
            _headers["X-chkp-sid"] = sid

        # create ssl context with no ssl verification, we do it by ourselves
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # create https connection
        conn = HTTPSConnection(server, self.port, context=context)
        '''
        # proxy socket
        user = 'proxy_login'
        passwd = 'proxy_pass'
        host = 'google.com'
        port = 443
        phost = 'proxy75.checkpoint.com'
        pport = 8080

        # setup basic authentication
        user_pass = base64.encodestring(user + ':' + passwd)
        proxy_authorization = 'Proxy-authorization: Basic ' + user_pass + '\r\n'
        proxy_connect = 'CONNECT %s:%s HTTP/1.0\r\n' % (host, port)
        user_agent = 'User-Agent: python\r\n'
        proxy_pieces = proxy_connect + user_agent + '\r\n'

        # now connect, very simple recv and error checking
        proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy.connect((phost, pport))
        proxy.sendall(proxy_pieces)
        response = proxy.recv(8192)
        status = response.split()[1]

        if status == str(200):
            conn.sock = proxy
        '''
        # set fingerprint
        conn.fingerprint = self.fingerprint

        # set debug level
        conn.set_debuglevel(self.http_debug_level)
        url = "/web_api/" + command

        try:
            # send the data to the Check Point server
            conn.request("POST", url, _data, _headers)
            # get the response from the Check Point server
            response = conn.getresponse()
            res = APIResponse(response)
    
        except ValueError as err:
            if (err.args[0]=="fingerprint value mismatch"):
                err_message = "Error: Fingerprint value mismatch:\n" + " Expecting : {}\n".format(err.args[1]) + " Got       : {}\n".format(err.args[2]) + "if you trust the new fingerprint, edit the 'fingerprints.txt' file."
                res = APIResponse("",err_message)
            else:
                res = APIResponse("",err)
        except Exception as inst:
            res = APIResponse("",inst)
                
        # when the command is 'login' we'd like to convert the password to "****" so that it would not appear in the debug file.                
        if command == "login":
            json_data = json.loads(_data)
            json_data["password"] = "****"
            _data = json.dumps(json_data)

        # store the request and the response (for debug purpose).
        _api_log = {}
        _api_log["request"] = {"url": url, "payload": json.loads(_data), "headers": _headers}
        _api_log["response"] = res.res_obj
        self.api_calls.append(_api_log)
        
        # If we want to wait for the task to end, wait for it 
        if wait_for_task is True and res.success and "task-id" in res.data:
            res = self.__wait_for_task(res.data["task-id"])
        elif wait_for_task is True and res.success and "tasks" in res.data:
            res = self.__wait_for_tasks(res.data["tasks"])
        
        return res

    #
    # get_server_fingerprint
    # ----------------------------------------------------
    # initiates an HTTPS connection to the server and extracts the SHA1 fingerprint from the server's certificate.
    #
    # arguments:
    #    server    - the IP address or name of the Check Point managemenet server
    #
    # return: string with SHA1 fingerprint (all uppercase letters)
    #
    def get_server_fingerprint(self, server):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        conn = HTTPSConnection(server, self.port, context=context)
        return conn.get_fingerprint_hash()

    #
    # __wait_for_task
    # ----------------------------------------------------
    # When the server needs to perfom an API call that may take a long time (e.g. run-script, install-policy, publish),
    # the server responds with a 'task-id'.
    # Using the show-task API it is possible to check on the status of this task until its completion.
    # Every two seconds, this function will check for the status of the task.
    # The function will return when the task (and its subtasks) are no longer in-progress.
    #
    # arguments:
    #    task-id       - the task identifier
    #
    def __wait_for_task(self, task_id):

        task_complete = False
        task_result = None
        in_progress = "in progress"
        
        # as long as there is a task in progress
        while not task_complete:
            
            # check the status of the task
            task_result = self.api_call("show-task", {"task-id": task_id, "details-level" : "full"}, self.server, 
                                            self.sid, False)
            
            # count the number of tasks that are not in-progress 
            completed_tasks = sum(1 for task in task_result.data["tasks"] if task["status"] != in_progress)

            # get the total number of tasks
            total_tasks = len(task_result.data["tasks"])

            # are we done?
            if completed_tasks == total_tasks:
                task_complete = True
            else:
                time.sleep(2) # wait 2 sec

        return task_result
    
    #
    # __wait_for_tasks
    # ----------------------------------------------------
    # The version of __wait_for_task function for the collection of tasks
    
    # arguments:
    #    tasks      - A list of tasks identifiers
    #
    def __wait_for_tasks(self, taskObjects):
        
        # A list of task ids to be retrieved
        tasks = []
        for taskObject in taskObjects :
            # Retrieve the taskId and wait for the task to be completed
            taskId = taskObject["task-id"]
            tasks.append(taskId)
            self.__wait_for_task(taskId)
        
        task_result = self.api_call("show-task", {"task-id": tasks, "details-level" : "full"}, self.server, 
                                        self.sid, False)
        
        return task_result
                
    #
    # api_query
    # ----------------------------------------------------
    # The APIs that return a list of objects are limited by the number of objects that they return.
    # To get the full list of objects, there's a need to make repeated API calls each time using a different offset
    # until all the objects are returned.
    # This API makes such repeated API calls and return the full list objects.
    # note: this function calls gen_api_query and iterates over the generator until it gets all the objects, then returns.
    #
    # arguments:
    #    command        - name of API command. This command should be an API that returns an array of objects (for example: show-hosts, show networks, ...)
    #    details-level  - query APIs always take a details-level argument. possible values are "standard", "full", "uid"
    #
    # return: an APIResponse object whose .data member contains a dict: { "objects": [...], "total": z }
    #
    def api_query(self, command, details_level="standard", container_key="objects"):
        for api_res in self.gen_api_query(command, details_level, [container_key]):
            if api_res.data["total"] == len(api_res.data[container_key]):
                del api_res.data["from"]
                del api_res.data["to"]
                return api_res

    #
    # check_fingerprint
    # ----------------------------------------------------
    # This function checks if the server's certificate is stored in the local fingerprints file.
    # If the server fingerprint is not found, it makes an https connection to the server and asks the user if he accepts the server fingerprint.
    # If the fingerprint is trusted, then it is stored in the fingerprint file.
    #
    #
    # arguments:
    #    server         - IP address / name of the Check Point management server
    #
    # return: false if the user does not accept the server certificate, 'true' in all other cases.
    #
    def check_fingerprint(self,server):
        
        # read the fingerprint from the local file
        local_fingerprint = self.read_fingerprint_from_file(server)
        server_fingerprint = self.get_server_fingerprint(server)

        # if the fingerprint is not stored on the local file
        if local_fingerprint == "" or local_fingerprint != server_fingerprint:
            # Get the server's fingerprint with a socket.
            if server_fingerprint == "":
                return False
            if local_fingerprint == "":
                print "You currently do not have a record of this server's fingerprint."
            else:
                print "The server's fingerprint is different from your local record of this server's fingerprint.\nYou maybe a victim to a Man-in-the-middle attack, please beware."
            print "Server's fingerprint: {}".format(server_fingerprint)
            if self.ask_yes_no_question("Do you accept this fingerprint?"):
                if self.save_fingerprint_to_file(server, server_fingerprint): # Save it.
                    print "Fingerprint saved."
                else:
                    print "Could not save fingerprint to file. Continuing anyway."
            else:
                return False
        self.fingerprint = local_fingerprint  # set the actual fingerprint in the class instance
        return True
    
    
    #
    # ask_yes_no_question
    # ----------------------------------------------------
    # helper function. Present a question to the user with Y/N options.
    #
    # arguments:
    #    question         - the question to display to the user 
    #
    # return: 'True' if the user typed 'Y'. 'False' is the user typed 'N'
    #
    @staticmethod
    def ask_yes_no_question(question):
        answer = raw_input(question + " [y/n] ")
        if answer.lower() == "y":
            return True
        else:
            return False

    #
    # save_fingerprint_to_file
    # ----------------------------------------------------
    # store a server's fingerprint into a local file.
    #
    # arguments:
    #    server         - the IP address/name of the Check Point management server.
    #    fingerprint    - A SHA1 fingerprint of the server's certificate.
    #    filename       - The file in which to store the certificates. The file will hold a JSON structure in which the key is the server and the value is its fingerprint.
    #
    # return: 'True' if everything went well. 'False' if there was some kind of error storing the fingerprint.
    #
    @staticmethod
    def save_fingerprint_to_file(server, fingerprint, filename="fingerprints.txt"):
        if not fingerprint:
            return False
        if os.path.isfile(filename):
            try:
                file = open(filename)
                buf = file.read()
                json_dict = json.loads(buf)
                file.close()
            except ValueError as e:
                if e.message == "No JSON object could be decoded":
                    print "Corrupt JSON file: " + filename
                else:
                    print e.message
                return False
            except Exception as e:
                print e
                return False
            else:
                if server in json_dict and json_dict[server] == fingerprint:
                    return True
                else:
                    json_dict[server] = fingerprint
        else:
            json_dict = {server: fingerprint}
        try:
            with open(filename, 'w') as filedump:
                json.dump(json_dict, filedump)
                filedump.close()
            return True
        except Exception as e:
            print e
            return False

    #
    # read_fingerprint_from_file
    # ----------------------------------------------------
    # reads a server's fingerprint from a local file.
    #
    # arguments:
    #    server         - the IP address/name of the Check Point management server.
    #    filename       - The file in which to store the certificates. The file will hold a JSON structure in which the key is the server and the value is its fingerprint.
    #
    # return: A SHA1 fingerprint of the server's certificate.
    #
    @staticmethod
    def read_fingerprint_from_file(server, filename="fingerprints.txt"):
        assert isinstance(server, basestring)

        if os.path.isfile(filename):
            file = open(filename)
            try:
                json_dict = json.load(file)
                file.close()
            except ValueError as e:
                if e.message == "No JSON object could be decoded":
                    print("Corrupt JSON file: " + filename, file=sys.stderr)
                else:
                    print(e.message, file=sys.stderr)
            except Exception as e:
                print(e, file=sys.stderr)
            else:
                # file is ok and readable.
                if server in json_dict:
                    return json_dict[server]
        return ""


#
#
# HTTPSConnection
# ----------------------------------------------------
# A class for making HTTPS connections that overrides the default HTTPS checks (e.g. not accepting self-signed-certificates) and replaces them with a server fingerprint check
#
#
class HTTPSConnection(httplib.HTTPSConnection):
    def connect(self):
        httplib.HTTPConnection.connect(self)
        self.sock = ssl.wrap_socket(
            self.sock, self.key_file, self.cert_file,
            cert_reqs=ssl.CERT_NONE)
        if getattr(self, 'fingerprint') is not None:
            digest = self.fingerprint
            alg = "SHA1"
            fingerprint = hashlib.new(
                alg, self.sock.getpeercert(True)).hexdigest().upper()
            if fingerprint != digest.replace(':', '').upper():
                raise ValueError('fingerprint value mismatch', fingerprint, digest.replace(':', '').upper())

    def get_fingerprint_hash(self):
        try:
            httplib.HTTPConnection.connect(self)
            self.sock = ssl.wrap_socket(
                self.sock, self.key_file, self.cert_file,
                cert_reqs=ssl.CERT_NONE)
        except Exception as err:
            return ""
        fingerprint = hashlib.new(
            "SHA1", self.sock.getpeercert(True)).hexdigest()
        return fingerprint.upper()

