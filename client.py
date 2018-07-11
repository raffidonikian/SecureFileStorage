"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError


class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        fromserver = self.storage_server.get(username + "keys")
        sigfromserver = self.storage_server.get(username + "keysig")
        if not fromserver:
            keys = self.crypto.get_random_bytes(48)
            toserver = self.crypto.asymmetric_encrypt(keys, self.pks.get_encryption_key(self.username))
            sigtoserver = self.crypto.asymmetric_sign(toserver, self.rsa_priv_key)
            self.storage_server.put(username + "keys", toserver)
            self.storage_server.put(username + "keysig", sigtoserver)
        else:
            check = self.crypto.asymmetric_verify(fromserver, sigfromserver, self.pks.get_signature_key(self.username))
            if not check:
                raise IntegrityError
            keys = self.crypto.asymmetric_decrypt(fromserver, self.elg_priv_key)
        self.encryption_key = keys[:32]
        self.mac_key = keys[32:64]
        self.filename_key = keys[64:]

    def path_join(self, *strings):
        return '/'.join(strings)

    def encrypt_mac_store(self, id, value, encryption_key, mac_key):
        if id is None:
            return None
        IVgen = self.crypto.get_random_bytes(16)
        encrypted_file = self.crypto.symmetric_encrypt(value, encryption_key, cipher_name='AES', mode_name='CBC', IV=IVgen, iv=None, counter=None, ctr=None, segment_size=128)
        mac = self.crypto.message_authentication_code(IVgen + encrypted_file, mac_key, hash_name='SHA256')
        tosend = mac + IVgen + encrypted_file
        self.storage_server.put(id, tosend)

    def mac_check_decrypt(self, id, decryption_key, mac_key):
        encrypted_file = self.storage_server.get(id)
        if encrypted_file is None:
            return None
        mac = encrypted_file[:64]
        IV = encrypted_file[64:96]
        encrypted_contents = encrypted_file[96:]
        mac_check = self.crypto.message_authentication_code(IV + encrypted_contents, mac_key, hash_name='SHA256')
        if mac != mac_check:
            raise IntegrityError
        return self.crypto.symmetric_decrypt(encrypted_contents, decryption_key, cipher_name='AES',mode_name='CBC', IV=IV, iv=None,counter=None, ctr=None, segment_size=128)

    def upload_shared(self, data, value):
        id = data[:32]
        encryption_key_for_file = data[32:64]
        mac_key_for_file = data[64:96]
        data = self.mac_check_decrypt(id, encryption_key_for_file, mac_key_for_file)
        if data[:7] == "<share>":
            return self.upload_shared(data[7:], value)
        self.encrypt_mac_store(id, value, encryption_key_for_file, mac_key_for_file)

    def upload(self, name, value):
        keypath = self.path_join(self.username, self.crypto.message_authentication_code(name, self.filename_key, hash_name = 'SHA256'))
        decrypted_resp = self.mac_check_decrypt(keypath, self.encryption_key, self.mac_key)
        if not decrypted_resp: # New file
            rand = self.crypto.get_random_bytes(48)
            id = rand[:32]
            encryption_key_for_file = rand[32:64]
            mac_key_for_file = rand[64:]
            self.encrypt_mac_store(keypath, rand+name, self.encryption_key, self.mac_key)
            self.encrypt_mac_store(id, value, encryption_key_for_file, mac_key_for_file)
        else: # File already exists, check signatures for keys and ID
            self.upload_shared(decrypted_resp, value)

    def download_shared(self, data):
        id = data[:32]
        encryption_key_for_file = data[32:64]
        mac_key_for_file = data[64:96]
        data = self.mac_check_decrypt(id, encryption_key_for_file, mac_key_for_file)
        if data is None:
            return None
        elif data[:7] == "<share>":
            return self.download_shared(data[7:])
        else:
            return data

    def download(self, name):
        keypath = self.path_join(self.username, self.crypto.message_authentication_code(name, self.filename_key, hash_name = 'SHA256'))
        decrypted_resp = self.mac_check_decrypt(keypath, self.encryption_key, self.mac_key)
        if decrypted_resp is None:
            return None
        return self.download_shared(decrypted_resp)

    def receive_share(self, from_username, newname, message):
        signature = message[:512]
        encrypted_share_data = message[512:]
        senders_sig_public = self.pks.get_signature_key(from_username)
        if not self.crypto.asymmetric_verify(encrypted_share_data, signature, senders_sig_public):
            raise IntegrityError
        decrypted_share_data = self.crypto.asymmetric_decrypt(encrypted_share_data, self.elg_priv_key)
        share_id = decrypted_share_data[:32]
        encryption_key_for_share = decrypted_share_data[32:64]
        mac_key_for_share = decrypted_share_data[64:]
        keypath = self.path_join(self.username, self.crypto.message_authentication_code(newname, self.filename_key, hash_name = 'SHA256'))
        key_data = share_id + encryption_key_for_share + mac_key_for_share
        self.encrypt_mac_store(keypath, key_data+newname, self.encryption_key, self.mac_key)

    def share(self, user, name):
        keypath = self.path_join(self.username, self.crypto.message_authentication_code(name, self.filename_key, hash_name = 'SHA256'))
        decrypted_resp = self.mac_check_decrypt(keypath, self.encryption_key, self.mac_key)
        if decrypted_resp is None:
            return None
        id = decrypted_resp[:32]
        encryption_key_for_file = decrypted_resp[32:64]
        mac_key_for_file = decrypted_resp[64:96]
        share_data = "<share>" + id + encryption_key_for_file + mac_key_for_file
        rand = self.crypto.get_random_bytes(48)
        share_id = rand[:32]
        encryption_key_for_share = rand[32:64]
        mac_key_for_share = rand[64:]
        unencrypted_to_add_to_share_list = user + '/' + share_id + encryption_key_for_share + mac_key_for_share + ' '
        sharepath = self.username + "share_list" + keypath
        temp = self.mac_check_decrypt(sharepath, self.encryption_key, self.mac_key)
        if temp is not None:
            unencrypted_to_add_to_share_list = unencrypted_to_add_to_share_list + temp
        self.encrypt_mac_store(sharepath, unencrypted_to_add_to_share_list, self.encryption_key, self.mac_key)
        self.encrypt_mac_store(share_id, share_data, encryption_key_for_share, mac_key_for_share)
        to_send_to_user = share_id + encryption_key_for_share + mac_key_for_share
        # Encrypt with their public key, sign with our private key
        their_public = self.pks.get_encryption_key(user)
        encrypted_to_send_to_user = self.crypto.asymmetric_encrypt(to_send_to_user, their_public)
        signature = self.crypto.asymmetric_sign(encrypted_to_send_to_user, self.rsa_priv_key)
        return signature + encrypted_to_send_to_user

    def revoke(self, user, name):
        keypath = self.path_join(self.username, self.crypto.message_authentication_code(name, self.filename_key, hash_name = 'SHA256'))
        sharepath = self.username + "share_list" + keypath
        cur_share_list = self.mac_check_decrypt(sharepath, self.encryption_key, self.mac_key)
        if cur_share_list is None:
            return
        cur_share_list = cur_share_list[:len(cur_share_list) - 1]
        list_as_array = cur_share_list.split(' ')
        names = [elem.split('/')[0] for elem in list_as_array]
        data_to_index = [elem.split('/')[1] for elem in list_as_array]
        index_of_removal = names.index(user)
        data = data_to_index[index_of_removal]
        data_to_index.pop(index_of_removal)
        list_as_array.pop(index_of_removal)
        cur_share_list = ' '.join(list_as_array)
        cur_share_list = cur_share_list + ' '
        self.encrypt_mac_store(sharepath, cur_share_list, self.encryption_key, self.mac_key)
        ID_to_delete = data[:32]
        self.storage_server.put(ID_to_delete, "byebyebye")
        rand = self.crypto.get_random_bytes(48)
        new_id = rand[:32]
        new_encryption_key_for_file = rand[32:64]
        new_mac_key_for_file = rand[64:]
        original_file = self.download(name)
        self.encrypt_mac_store(keypath, rand+name, self.encryption_key, self.mac_key)
        self.encrypt_mac_store(new_id, original_file, new_encryption_key_for_file, new_mac_key_for_file)
        share_data = "<share>" + new_id + new_encryption_key_for_file + new_mac_key_for_file
        for elem in data_to_index:
            share_id = elem[:32]
            encryption_key_for_share = elem[32:64]
            mac_key_for_share = elem[64:]
            self.encrypt_mac_store(share_id, share_data, encryption_key_for_share, mac_key_for_share)
