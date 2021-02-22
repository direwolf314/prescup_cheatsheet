#!/usr/bin/env python

import subprocess
import json
import pprint

'''
The Bitcoin addresses (public keys) associated with each user are shown
in the following table:

 User      BTC Address                           
:---------:--------------------------------------
 Koinbase  "2NFRCaDA6LLd9gqKbygmD1HRj992T6KwM4k" 
 Allie     "2NF2tXr1qxzyVZe1A3PJzfeMy8kkGxwAkt2" 
 Bubba     "2N2pxfcWsLQgkmEEo9B7yPnb3pJbcipyi9g" 
 Chuck     "2N8YHRTnbu4Jv3unDGFbfDNXn8QCeihbf4A" 
 DeeDee    "2Mz1uxd5bZENNQtzjcKh5dcdXXh6qZtfwkg" 


The list of known illegal transactions made available to Koinbase by law
enforcement currently contains the following entry:

"""
8d6e482252f84eaeeada387efb9ce56563ffc5bc42e4ec9d9119cfd4a6964611
'''

users = { "2NFRCaDA6LLd9gqKbygmD1HRj992T6KwM4k" : "[KOINBASE]",
        "2NF2tXr1qxzyVZe1A3PJzfeMy8kkGxwAkt2" : "[ALLIE]"     ,
        "2N2pxfcWsLQgkmEEo9B7yPnb3pJbcipyi9g":"[BUBBA]"     ,
        "2N8YHRTnbu4Jv3unDGFbfDNXn8QCeihbf4A" : "[CHUCK]"    ,
        "2Mz1uxd5bZENNQtzjcKh5dcdXXh6qZtfwkg": "[DEEDEE]" }

bad_transaction = "8d6e482252f84eaeeada387efb9ce56563ffc5bc42e4ec9d9119cfd4a6964611"

tip = "47448ed59ecb35e5eec31bb6caa91d19cfe52093e61cae7450b769eb1751d5cc"

class Block():
    def __init__(self, i, prev, transactions):
        self.id = i
        self.prev = prev
        self.next = ''
        self.transactions = transactions

    def __str__(self):
        return '[Block]: %s %s %s \n\t%s' % (self.id, self.prev, self.next, '\n\t'.join([str(x) for x in self.transactions]))

class Transaction():
    def __init__(self, i, value, prev, dest):
        self.id = i
        self.value = value
        self.prev = prev
        self.dest = dest

    def __str__(self):
        prev_filter = [x if x != bad_transaction else "[ILLEGAL TRANSACTION]" for x in self.prev]
        return '[Transaction]: %s %f %s %s' % (self.id if self.id != bad_transaction else "[ILLEGAL TRANSACTION]", self.value, ','.join(prev_filter), self.dest if self.dest not in users else users[self.dest])


def parse_transaction(tx):
    #print tx
    i = tx['txid']
    prev = []
    for vin in tx['vin']:
        try:
            prev.append(vin['txid'])
        except:
            pass

    for o in tx['vout']:
        if o['value'] > 0: # might miss some here
            value = o['value']
            dest = o['scriptPubKey']['addresses'][0]
            transaction = Transaction(i, value, prev, dest)
            #print transaction
            return transaction


def cli_block(blkid):
    out = subprocess.check_output(('bitcoin-cli -regtest getblock %s 2' % blkid).split())
    j = json.loads(out)
    transactions = []
    for t in j['tx']:
        transactions.append(parse_transaction(t))

    b = Block(j['hash'], j['previousblockhash'], transactions)
    print b
    return b

def main():
    block_id = tip
    while True:
        try:
            block = cli_block(block_id)
        except:
            return
        for tx in block.transactions:
            if tx.id == bad_transaction:
                print "found"
                #return
        block_id = block.prev

if __name__ == '__main__':
    main()
