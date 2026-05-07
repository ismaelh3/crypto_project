#python3

import socket
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


class SiFT_MTP_Error(Exception):
    def __init__(self, err_msg):
        self.err_msg = err_msg


class SiFT_MTP:
    def __init__(self, peer_socket):

        self.DEBUG = True

        # --------- CONSTANTS ------------
        self.version_major = 1
        self.version_minor = 0
        self.msg_hdr_ver = b'\x01\x00'

        self.size_msg_hdr = 16
        self.size_msg_hdr_ver = 2
        self.size_msg_hdr_typ = 2
        self.size_msg_hdr_len = 2
        self.size_msg_hdr_sqn = 2
        self.size_msg_hdr_rnd = 6
        self.size_msg_hdr_rsv = 2

        self.msg_hdr_rsv = b'\x00\x00'

        self.size_msg_mac = 12
        self.size_msg_etk = 256
        self.size_tmp_key = 32
        self.max_msg_len = 65535

        self.type_login_req =    b'\x00\x00'
        self.type_login_res =    b'\x00\x10'
        self.type_command_req =  b'\x01\x00'
        self.type_command_res =  b'\x01\x10'
        self.type_upload_req_0 = b'\x02\x00'
        self.type_upload_req_1 = b'\x02\x01'
        self.type_upload_res =   b'\x02\x10'
        self.type_dnload_req =   b'\x03\x00'
        self.type_dnload_res_0 = b'\x03\x10'
        self.type_dnload_res_1 = b'\x03\x11'

        self.msg_types = (
            self.type_login_req, self.type_login_res,
            self.type_command_req, self.type_command_res,
            self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
            self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1
        )

        # --------- STATE ------------
        self.peer_socket = peer_socket

        # login-phase temporary key tk
        self.temp_key = None

        # final transfer key
        self.transfer_key = None

        # RSA keys for login_req processing
        self.server_public_key = None
        self.server_private_key = None

        # sequence numbers start from 1 for sending
        self.send_sqn = 1

        # last received sequence number
        self.last_recv_sqn = 0

    # -------------------------------------------------------------------------
    # Key setup helpers
    # -------------------------------------------------------------------------

    def set_server_public_key(self, key):
        if isinstance(key, RSA.RsaKey):
            self.server_public_key = key.publickey() if key.has_private() else key
        else:
            imported = RSA.import_key(key)
            self.server_public_key = imported.publickey() if imported.has_private() else imported

    def set_server_private_key(self, key):
        if isinstance(key, RSA.RsaKey):
            if not key.has_private():
                raise SiFT_MTP_Error('Private RSA key required')
            self.server_private_key = key
        else:
            imported = RSA.import_key(key)
            if not imported.has_private():
                raise SiFT_MTP_Error('Private RSA key required')
            self.server_private_key = imported

    def set_temp_key(self, key):
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise SiFT_MTP_Error('Temporary key must be 32 bytes')
        self.temp_key = bytes(key)

    def set_transfer_key(self, key):
        if not isinstance(key, (bytes, bytearray)) or len(key) not in (16, 24, 32):
            raise SiFT_MTP_Error('Invalid transfer key length')
        self.transfer_key = bytes(key)

    # -------------------------------------------------------------------------
    # Header helpers
    # -------------------------------------------------------------------------

    def parse_msg_header(self, msg_hdr):
        if len(msg_hdr) != self.size_msg_hdr:
            raise SiFT_MTP_Error('Invalid message header size')

        parsed_msg_hdr, i = {}, 0
        parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver
        parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
        parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
        parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
        parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
        parsed_msg_hdr['rsv'], i = msg_hdr[i:i+self.size_msg_hdr_rsv], i+self.size_msg_hdr_rsv
        return parsed_msg_hdr

    def build_msg_header(self, msg_type, msg_len, sqn, rnd):
        if msg_type not in self.msg_types:
            raise SiFT_MTP_Error('Unknown message type')

        if not isinstance(rnd, (bytes, bytearray)) or len(rnd) != 6:
            raise SiFT_MTP_Error('Random field must be 6 bytes')

        if not (1 <= sqn <= 0xFFFF):
            raise SiFT_MTP_Error('Sequence number out of range')

        if not (self.size_msg_hdr <= msg_len <= self.max_msg_len):
            raise SiFT_MTP_Error('Invalid message length')

        return (
            self.msg_hdr_ver +
            msg_type +
            msg_len.to_bytes(2, byteorder='big') +
            sqn.to_bytes(2, byteorder='big') +
            bytes(rnd) +
            self.msg_hdr_rsv
        )

    def validate_msg_header(self, parsed_msg_hdr):
        if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
            raise SiFT_MTP_Error('Unsupported version found in message header')

        if parsed_msg_hdr['typ'] not in self.msg_types:
            raise SiFT_MTP_Error('Unknown message type found in message header')

        if parsed_msg_hdr['rsv'] != self.msg_hdr_rsv:
            raise SiFT_MTP_Error('Invalid reserved field in message header')

        msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
        if msg_len < self.size_msg_hdr + self.size_msg_mac:
            raise SiFT_MTP_Error('Message length too small')

        return msg_len

    def build_nonce(self, parsed_msg_hdr):
        # Spec requirement: nonce = sqn || rnd
        return parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']

    # -------------------------------------------------------------------------
    # Socket helpers
    # -------------------------------------------------------------------------

    def receive_bytes(self, n):
        bytes_received = b''
        bytes_count = 0

        while bytes_count < n:
            try:
                chunk = self.peer_socket.recv(n - bytes_count)
            except Exception:
                raise SiFT_MTP_Error('Unable to receive via peer socket')

            if not chunk:
                raise SiFT_MTP_Error('Connection with peer is broken')

            bytes_received += chunk
            bytes_count += len(chunk)

        return bytes_received

    def send_bytes(self, bytes_to_send):
        try:
            self.peer_socket.sendall(bytes_to_send)
        except Exception:
            raise SiFT_MTP_Error('Unable to send via peer socket')

    def close_connection(self):
        try:
            self.peer_socket.close()
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Crypto helpers
    # -------------------------------------------------------------------------

    def encrypt_gcm(self, key, nonce, aad, plaintext):
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac)
            cipher.update(aad)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext)
            return ciphertext, tag
        except Exception as e:
            raise SiFT_MTP_Error('AES-GCM encryption failed --> ' + str(e))

    def decrypt_gcm(self, key, nonce, aad, ciphertext, tag):
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac)
            cipher.update(aad)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext
        except Exception:
            raise SiFT_MTP_Error('AES-GCM authentication/decryption failed')

    def rsa_encrypt_temp_key(self, temp_key):
        if self.server_public_key is None:
            raise SiFT_MTP_Error('Server public key is not set')

        try:
            rsa_cipher = PKCS1_OAEP.new(self.server_public_key)
            etk = rsa_cipher.encrypt(temp_key)
        except Exception as e:
            raise SiFT_MTP_Error('RSA-OAEP encryption failed --> ' + str(e))

        if len(etk) != self.size_msg_etk:
            raise SiFT_MTP_Error('Encrypted temporary key has invalid size')

        return etk

    def rsa_decrypt_temp_key(self, etk):
        if self.server_private_key is None:
            raise SiFT_MTP_Error('Server private key is not set')

        if len(etk) != self.size_msg_etk:
            raise SiFT_MTP_Error('Encrypted temporary key has invalid size')

        try:
            rsa_cipher = PKCS1_OAEP.new(self.server_private_key)
            temp_key = rsa_cipher.decrypt(etk)
        except Exception:
            raise SiFT_MTP_Error('RSA-OAEP decryption failed')

        if len(temp_key) != self.size_tmp_key:
            raise SiFT_MTP_Error('Temporary key has invalid size')

        return temp_key

    # -------------------------------------------------------------------------
    # Key selection
    # -------------------------------------------------------------------------

    def get_send_key(self, msg_type):
        # login_req: fresh temp key generated inside send_msg
        # login_res: use temp_key already learned from login_req
        # others: use transfer_key
        if msg_type == self.type_login_res:
            if self.temp_key is None:
                raise SiFT_MTP_Error('Temporary key is not set for login response')
            return self.temp_key

        if msg_type == self.type_login_req:
            return None

        if self.transfer_key is None:
            raise SiFT_MTP_Error('Transfer key is not set')
        return self.transfer_key

    def get_receive_key(self, msg_type):
        if msg_type == self.type_login_req:
            return None

        if msg_type == self.type_login_res:
            if self.temp_key is None:
                raise SiFT_MTP_Error('Temporary key is not set for login response')
            return self.temp_key

        if self.transfer_key is None:
            raise SiFT_MTP_Error('Transfer key is not set')
        return self.transfer_key

    # -------------------------------------------------------------------------
    # Receive message
    # -------------------------------------------------------------------------

    def receive_msg(self):
        try:
            msg_hdr = self.receive_bytes(self.size_msg_hdr)
            if len(msg_hdr) != self.size_msg_hdr:
                raise SiFT_MTP_Error('Incomplete message header received')

            parsed_msg_hdr = self.parse_msg_header(msg_hdr)
            msg_len = self.validate_msg_header(parsed_msg_hdr)

            sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')
            if sqn <= self.last_recv_sqn:
                raise SiFT_MTP_Error('Replay or out-of-order message detected')

            msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
            if len(msg_body) != msg_len - self.size_msg_hdr:
                raise SiFT_MTP_Error('Incomplete message body received')

            msg_type = parsed_msg_hdr['typ']
            nonce = self.build_nonce(parsed_msg_hdr)

            # login request: epd || mac || etk
            if msg_type == self.type_login_req:
                if len(msg_body) < self.size_msg_mac + self.size_msg_etk:
                    raise SiFT_MTP_Error('Login request body too short')

                ciphertext = msg_body[:-(self.size_msg_mac + self.size_msg_etk)]
                tag = msg_body[-(self.size_msg_mac + self.size_msg_etk):-self.size_msg_etk]
                etk = msg_body[-self.size_msg_etk:]

                tk = self.rsa_decrypt_temp_key(etk)
                plaintext = self.decrypt_gcm(tk, nonce, msg_hdr, ciphertext, tag)

                # store temp key so server can use it for login_res
                self.temp_key = tk

                if self.DEBUG:
                    print('MTP login_req received (' + str(msg_len) + '):')
                    print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
                    print('EPD (' + str(len(ciphertext)) + '): ' + ciphertext.hex())
                    print('MAC (' + str(len(tag)) + '): ' + tag.hex())
                    print('ETK (' + str(len(etk)) + '): ' + etk.hex())
                    print('PLD (' + str(len(plaintext)) + '): ' + plaintext.hex())
                    print('------------------------------------------')

            else:
                if len(msg_body) < self.size_msg_mac:
                    raise SiFT_MTP_Error('Message body too short')

                ciphertext = msg_body[:-self.size_msg_mac]
                tag = msg_body[-self.size_msg_mac:]

                key = self.get_receive_key(msg_type)
                plaintext = self.decrypt_gcm(key, nonce, msg_hdr, ciphertext, tag)

                if self.DEBUG:
                    print('MTP message received (' + str(msg_len) + '):')
                    print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
                    print('EPD (' + str(len(ciphertext)) + '): ' + ciphertext.hex())
                    print('MAC (' + str(len(tag)) + '): ' + tag.hex())
                    print('PLD (' + str(len(plaintext)) + '): ' + plaintext.hex())
                    print('------------------------------------------')

            self.last_recv_sqn = sqn
            return msg_type, plaintext

        except SiFT_MTP_Error:
            self.close_connection()
            raise
        except Exception as e:
            self.close_connection()
            raise SiFT_MTP_Error('Unexpected receive failure --> ' + str(e))

    # -------------------------------------------------------------------------
    # Send message
    # -------------------------------------------------------------------------

    def send_msg(self, msg_type, msg_payload):
        try:
            if msg_type not in self.msg_types:
                raise SiFT_MTP_Error('Unknown message type')

            if not isinstance(msg_payload, (bytes, bytearray)):
                raise SiFT_MTP_Error('Message payload must be bytes')

            msg_payload = bytes(msg_payload)
            sqn = self.send_sqn
            rnd = get_random_bytes(6)

            # login request: use fresh temporary key, then append etk
            if msg_type == self.type_login_req:
                tk = get_random_bytes(self.size_tmp_key)

                msg_len = self.size_msg_hdr + len(msg_payload) + self.size_msg_mac + self.size_msg_etk
                msg_hdr = self.build_msg_header(msg_type, msg_len, sqn, rnd)
                parsed_msg_hdr = self.parse_msg_header(msg_hdr)
                nonce = self.build_nonce(parsed_msg_hdr)

                ciphertext, tag = self.encrypt_gcm(tk, nonce, msg_hdr, msg_payload)
                etk = self.rsa_encrypt_temp_key(tk)

                msg = msg_hdr + ciphertext + tag + etk

                # store temp key so client can use it for login_res
                self.temp_key = tk

                if self.DEBUG:
                    print('MTP login_req to send (' + str(msg_len) + '):')
                    print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
                    print('PLD (' + str(len(msg_payload)) + '): ' + msg_payload.hex())
                    print('EPD (' + str(len(ciphertext)) + '): ' + ciphertext.hex())
                    print('MAC (' + str(len(tag)) + '): ' + tag.hex())
                    print('ETK (' + str(len(etk)) + '): ' + etk.hex())
                    print('------------------------------------------')

            else:
                key = self.get_send_key(msg_type)

                msg_len = self.size_msg_hdr + len(msg_payload) + self.size_msg_mac
                msg_hdr = self.build_msg_header(msg_type, msg_len, sqn, rnd)
                parsed_msg_hdr = self.parse_msg_header(msg_hdr)
                nonce = self.build_nonce(parsed_msg_hdr)

                ciphertext, tag = self.encrypt_gcm(key, nonce, msg_hdr, msg_payload)
                msg = msg_hdr + ciphertext + tag

                if self.DEBUG:
                    print('MTP message to send (' + str(msg_len) + '):')
                    print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
                    print('PLD (' + str(len(msg_payload)) + '): ' + msg_payload.hex())
                    print('EPD (' + str(len(ciphertext)) + '): ' + ciphertext.hex())
                    print('MAC (' + str(len(tag)) + '): ' + tag.hex())
                    print('------------------------------------------')

            self.send_bytes(msg)
            self.send_sqn += 1

        except SiFT_MTP_Error:
            self.close_connection()
            raise
        except Exception as e:
            self.close_connection()
            raise SiFT_MTP_Error('Unexpected send failure --> ' + str(e))