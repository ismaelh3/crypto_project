# python3

import time
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Random import get_random_bytes
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error

class SiFT_LOGIN_Error(Exception):
    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_LOGIN:
    def __init__(self, mtp):

        self.DEBUG = True

        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'

        # Timestamp Window: +- 1 Second
        self.timestamp_window_ns = 2_000_000_000

        # --------- STATE ------------
        self.mtp = mtp
        self.server_users = None

    def set_server_private_key(self, key):
        self.mtp.set_server_private_key(key)

    def set_server_public_key(self, key):
        self.mtp.set_server_public_key(key)

    # sets user passwords dictionary (to be used by the server)
    def set_server_users(self, users):
        self.server_users = users

    # builds a login request from a dictionary
    # v1.0 format:
    # <timestamp>\n
    # <username>\n
    # <password>\n
    # <client_random>
    def build_login_req(self, login_req_struct):

        login_req_str = str(login_req_struct['timestamp'])
        login_req_str += self.delimiter + login_req_struct['username']
        login_req_str += self.delimiter + login_req_struct['password']
        login_req_str += self.delimiter + login_req_struct['client_random'].hex()

        return login_req_str.encode(self.coding)

    # parses a login request into a dictionary
    def parse_login_req(self, login_req):

        login_req_fields = login_req.decode(self.coding).split(self.delimiter)
        login_req_struct = {}
        login_req_struct['timestamp'] = int(login_req_fields[0])
        login_req_struct['username'] = login_req_fields[1]
        login_req_struct['password'] = login_req_fields[2]
        login_req_struct['client_random'] = bytes.fromhex(login_req_fields[3])

        return login_req_struct

    # builds a login response from a dictionary
    # v1.0 format:
    # <request_hash>\n
    # <server_random>
    def build_login_res(self, login_res_struct):

        login_res_str = login_res_struct['request_hash'].hex()
        login_res_str += self.delimiter + login_res_struct['server_random'].hex()

        return login_res_str.encode(self.coding)

    # parses a login response into a dictionary
    def parse_login_res(self, login_res):

        try:
            login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        except Exception:
            raise SiFT_LOGIN_Error('Unable to decode login response')

        if len(login_res_fields) != 2:
            raise SiFT_LOGIN_Error('Malformed login response')

        login_res_struct = {}

        try:
            login_res_struct['request_hash'] = bytes.fromhex(login_res_fields[0])
        except ValueError:
            raise SiFT_LOGIN_Error('Invalid request_hash in login response')

        try:
            login_res_struct['server_random'] = bytes.fromhex(login_res_fields[1])
        except ValueError:
            raise SiFT_LOGIN_Error('Invalid server_random in login response')

        if len(login_res_struct['server_random']) != 16:
            raise SiFT_LOGIN_Error('server_random must be 16 bytes long')

        return login_res_struct

    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):

        pwdhash = PBKDF2(
            pwd,
            usr_struct['salt'],
            len(usr_struct['pwdhash']),
            count=usr_struct['icount'],
            hmac_hash_module=SHA256
        )

        return pwdhash == usr_struct['pwdhash']

    # checks freshness of timestamp according to configured acceptance window
    def check_timestamp(self, timestamp_ns):

        now_ns = time.time_ns()
        half_window = self.timestamp_window_ns // 2

        if timestamp_ns < now_ns - half_window:
            return False

        if timestamp_ns > now_ns + half_window:
            return False

        return True

    # derives the final 32-byte transfer key for MTP
    # IKM = client_random || server_random
    # salt = request_hash
    # HKDF-SHA256, key length 32 bytes
    def derive_transfer_key(self, client_random, server_random, request_hash):

        ikm = client_random + server_random

        transfer_key = HKDF(
            master=ikm,
            key_len=32,
            salt=request_hash,
            hashmod=SHA256,
            num_keys=1
        )

        return transfer_key

    # handles login process (to be used by the server)
    def handle_login_server(self):

        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')

        # trying to receive a login request
        # In v1.0 this assumes MTP:
        # - verifies/decrypts login request
        # - returns plaintext payload
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)

        # DEBUG
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            try:
                print(msg_payload[:min(512, len(msg_payload))].decode('utf-8'))
            except Exception:
                print(msg_payload[:min(512, len(msg_payload))])
            print('------------------------------------------')
        # DEBUG

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        # processing login request
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        login_req_struct = self.parse_login_req(msg_payload)

        # check timestamp freshness
        if not self.check_timestamp(login_req_struct['timestamp']):
            raise SiFT_LOGIN_Error('Timestamp verification failed')

        # checking username and password
        if login_req_struct['username'] in self.server_users:
            if not self.check_password(
                login_req_struct['password'],
                self.server_users[login_req_struct['username']]
            ):
                raise SiFT_LOGIN_Error('Password verification failed')
        else:
            raise SiFT_LOGIN_Error('Unknown user attempted to log in')

        # building login response
        login_res_struct = {}
        login_res_struct['request_hash'] = request_hash
        login_res_struct['server_random'] = get_random_bytes(16)

        msg_payload = self.build_login_res(login_res_struct)

        # DEBUG
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:min(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG

        # sending login response
        # In v1.0 this assumes MTP sends the login response
        # using the temporary key recovered from the login request.
        try:
            self.mtp.send_msg(self.mtp.type_login_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login response --> ' + e.err_msg)

        # derive and install final transfer key
        transfer_key = self.derive_transfer_key(
            login_req_struct['client_random'],
            login_res_struct['server_random'],
            request_hash
        )

        try:
            self.mtp.set_transfer_key(transfer_key)
        except AttributeError:
            raise SiFT_LOGIN_Error('MTP implementation must provide set_transfer_key() in v1.0')
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to install final transfer key --> ' + e.err_msg)

        # DEBUG
        if self.DEBUG:
            print('User ' + login_req_struct['username'] + ' logged in')
            print('Final transfer key installed at server')
        # DEBUG

        return login_req_struct['username']

    # handles login process (to be used by the client)
    def handle_login_client(self, username, password):

        # building a login request
        login_req_struct = {}
        login_req_struct['timestamp'] = time.time_ns()
        login_req_struct['username'] = username
        login_req_struct['password'] = password
        login_req_struct['client_random'] = get_random_bytes(16)

        msg_payload = self.build_login_req(login_req_struct)

        # DEBUG
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:min(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG

        # trying to send login request
        # In v1.0 this assumes MTP:
        # - creates temporary key tk
        # - encrypts payload with AES-GCM under tk
        # - encrypts tk with server public key
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        # computing hash of sent request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # trying to receive a login response
        # In v1.0 this assumes MTP:
        # - verifies/decrypts login response using temporary key tk
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        # DEBUG
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            try:
                print(msg_payload[:min(512, len(msg_payload))].decode('utf-8'))
            except Exception:
                print(msg_payload[:min(512, len(msg_payload))])
            print('------------------------------------------')
        # DEBUG

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        # processing login response
        login_res_struct = self.parse_login_res(msg_payload)

        # checking request_hash received in the login response
        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')

        # derive and install final transfer key
        transfer_key = self.derive_transfer_key(
            login_req_struct['client_random'],
            login_res_struct['server_random'],
            request_hash
        )

        try:
            self.mtp.set_transfer_key(transfer_key)
        except AttributeError:
            raise SiFT_LOGIN_Error('MTP implementation must provide set_transfer_key() in v1.0')
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to install final transfer key --> ' + e.err_msg)

        # DEBUG
        if self.DEBUG:
            print('Final transfer key installed at client')
        # DEBUG