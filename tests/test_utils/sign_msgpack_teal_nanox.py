
from ledgerblue.comm import getDongle
import struct
import algosdk
from algosdk.future import transaction
import base64
import os
import sys
import inspect
import nacl.signing
from Cryptodome.Hash import SHA256



currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

from test import  txn_utils


def get_app_create_txn():
    approve_app = b'\x02 \x05\x00\x05\x04\x02\x01&\x07\x04vote\tVoteBegin\x07VoteEnd\x05voted\x08RegBegin\x06RegEnd\x07Creator1\x18"\x12@\x00\x951\x19\x12@\x00\x871\x19$\x12@\x00y1\x19%\x12@\x00R1\x19!\x04\x12@\x00<6\x1a\x00(\x12@\x00\x01\x002\x06)d\x0f2\x06*d\x0e\x10@\x00\x01\x00"2\x08+c5\x005\x014\x00A\x00\x02"C6\x1a\x016\x1a\x01d!\x04\x08g"+6\x1a\x01f!\x04C2\x06\'\x04d\x0f2\x06\'\x05d\x0e\x10C"2\x08+c5\x005\x012\x06*d\x0e4\x00\x10A\x00\t4\x014\x01d!\x04\tg!\x04C1\x00\'\x06d\x12C1\x00\'\x06d\x12C\'\x061\x00g1\x1b$\x12@\x00\x01\x00\'\x046\x1a\x00\x17g\'\x056\x1a\x01\x17g)6\x1a\x02\x17g*6\x1a\x03\x17g!\x04C'
    clear_pgm = b'\x02 \x01\x01' 
    clear_pgm =clear_pgm + (2048 - len(clear_pgm))*b'\x22' 

    # the approve_app is a compiled Tealscript taken from https://pyteal.readthedocs.io/en/stable/examples.html#periodic-payment
    # we truncated the pgm because of the memory limit on the Ledeger 
    approve_app = approve_app + (2048 - len(approve_app))*b'\x22'
    local_ints = 2
    local_bytes = 5
    global_ints = 24 
    global_bytes = 1
    args = [b'/x65/x87',
            b'/x68/x87',
            b'/x61/x87',
            b'/x62/x87',
            b'/x63/x87',
            b'/x64/x87',
            b'/x90/x87',
            b'/x91/x87',
            b'/x91/x87',
            b'/x92/x87',
            b'/x93/x87',
            b'/x94/x87',
            b'/x95/x87',
            b'/x96/x87',
            (32 -(8*14))*b'A']
    global_schema = transaction.StateSchema(global_ints, global_bytes)
    local_schema = transaction.StateSchema(local_ints, local_bytes)
    local_sp = transaction.SuggestedParams(fee= 2100, first=6002000, last=6003000,
                                    gen="testnet-v1.0",
                                    gh="SGO1GKSzyE7IEPItTxCByw9x8FmnrCDexi9/cOUJOiI=",flat_fee=True)
    txn = algosdk.future.transaction.ApplicationCreateTxn(sender="YK54TGVZ37C7P76GKLXTY2LAH2522VD3U2434HRKE7NMXA65VHJVLFVOE4",
                                                         sp=local_sp, approval_program=approve_app, on_complete=transaction.OnComplete.NoOpOC.real,clear_program= clear_pgm, global_schema=global_schema, 
                                                         
                                                         foreign_apps=[55,22], foreign_assets=[31566704,31566708], accounts=["7PKXMJB2577SQ6R6IGYRAZQ27TOOOTIGTOQGJB3L5SGZFBVVI4AHMKLCEI",
                                                                                                                            "NWBZBIROXZQEETCDKX6IZVVBV4EY637KCIX56LE5EHIQERCTSDYGXWG6PU",
                                                                                                                            "RP7BOFGBCPNHWPRJEGPNNQRNC3WXJUUAVSBTHMGUXLF36IEHSBGJOHOYZ4",
                                                                                                                            "LHHQJ6UMXRGEPXBVFKT7SY26BQOIK64VVPCLVRL3RNQLX5ZMBYG6ZHZMBE"],
                                                         app_args=args,
                                                         local_schema=local_schema )
    return txn

def hash_bytes(bytes_array):
    h = SHA256.new()
    h.update(bytes_array)
    return base64.b64encode(h.digest()).decode('ascii')


if __name__ == '__main__':
    dongle = getDongle(True)

    apdu = struct.pack('>BBBBB', 0x80, 0x3, 0x0, 0x0, 0x0)
    pubKey = dongle.exchange(apdu)

    print("---------------")
    print("public key: ", type(pubKey))
    print("---------------")

    txn = get_app_create_txn()

    print("---------------")
    print("approval app hash: ",hash_bytes(txn.approval_program).lower())
    print("---------------")

    print("---------------")
    print("clear app hash:  ",hash_bytes(txn.clear_program).lower())
    print("---------------")

    for i in range(15):
        print("---------------")
        print("arg hash: ",hash_bytes(txn.app_args[i]).lower())
        print("---------------")

        
    decoded_txn = base64.b64decode(algosdk.encoding.msgpack_encode(txn))

    sig = txn_utils.sign_algo_txn(dongle, decoded_txn)
    
    verify_key = nacl.signing.VerifyKey(bytes(pubKey))
    verify_key.verify(smessage=b'TX' + decoded_txn, signature=bytes(sig))
