# Ethereum State Channels in Python

I really enjoyed [Matthew Di Ferrante’s tutorial](https://medium.com/@matthewdif/ethereum-payment-channel-in-50-lines-of-code-a94fad2704bc) for a state channel written in solidity, but I found myself at a loss, along with many other commenters, on how to actually implement them. I decided to try it out in Python and create a tutorial to better understand setting up and interacting with a state channel. Obviously you wouldn't actually need a state-channel written in Python but going through the motions helped me understand what is going on in the Solidity example.

## Background Story
To quickly sum up, Bob wants to pay Alice a small amount of cryptocurrency every time she does a bit a work for him. Each payment amount is small enough that gas fees will significantly eat into Alice’s revenue if each transaction is recorded to the network. In this implementation of a state channel, Bob sends Alice a signed piece of data after each bit of work Alice does. This signed piece of data is special in that it contains all the information sufficient to trustlessly pay Alice when sent to a state channel contract (as implemented below). When Alice has finished all her tasks, she only has to send the final signed piece of data from Bob to the network, and receive all her cryptocurrency. For more detail than this see Matthew’s tutorial above.

## Python Example
### The Contract

(For simplicities sake I have left out the time-limit bit from Matthew’s tutorial as I was mostly interested in the message signing)

Here is the Matthew’s state-channel contract recreated in Python. For a real decentralized application, this should live on-chain but I was too lazy to deploy one and interact with it so I just made it in Python for testing instead.

```python
from ethereum.utils import privtoaddr, ecrecover_to_pub, ecsign
from eth_utils import keccak, encode_hex, decode_hex, to_checksum_address
from pprint import pprint
```

```python
def ecrecover(h, v, r, s):
    """
    Function recreating solidity's ecrecover

    Args:
        h: The Keccak hash of the msg
        v: The "v" parameter derived from the signed message (ethereum.utils.ecsign)
        r: The "r" parameter derived from the signed message (ethereum.utils.ecsign)
        s: The "s" parameter derived from the signed message (ethereum.utils.ecsign)

    Returns:
        Address of the message signer as a hexidecimal string
    """
    pub = ecrecover_to_pub(h, v, r, s)
    addr = keccak(pub)[-20:]
    addr = encode_hex(addr)
    addr = to_checksum_address(addr)
    return addr
```
```python
class Channel:

    
    def __init__(self, sender, recipient, deposit):
        self.sender = to_checksum_address(sender)
        self.recipient = to_checksum_address(recipient)
        self.deposit = deposit
        self.signatures = {}
    
    
    def close_channel(self, h, v, r, s, value):
        """
        Function recreating Matthew Di Ferrante's closure of a state channel in Python

        Args:
            h: The Keccak hash of the msg
            v: The "v" parameter derived from the hashed and signed message (ethereum.utils.ecsign)
            r: The "r" parameter derived from the hashed and signed message (ethereum.utils.ecsign)
            s: The "s" parameter derived from the hashed and signed message (ethereum.utils.ecsign)
            value: the 

        Returns:
            Address of the message signer as a hexidecimal string
        """
        
        # Recover the message signer's address
        # v, r, and s are specific to the message that was hashed and signed.
        # Changing any of these parameters produces a different address 
        # This also proves that h is the hashed message that was signed to produce v, r, and s
        signer = ecrecover(h, v, r, s)
        
        # Ensure that the signer is either the sender (Bob) or recipient (Alice) of the channel's ETH
        if (signer != self.recipient) and (signer != self.sender):
            assert False
        
        # Ensure that that value matches the signed message
        # Including the contract's hash ensures that the signed message can only be used in this channel
        proof = keccak(str(self.__hash__()) + value)
        if (proof != h):
            assert False
        
        # If this is the first time associate the proof with the first signer
        # Doesn't matter if Alice submits her signature or Bob's signature first
        # Or even if Bob submits his own signature first
        if not self.signatures.get(proof):
            self.signatures[proof] = signer
        # Continue from here only when the second signature makes an appearance
        elif (self.signatures.get(proof) != signer):
            # -- psuedo-code -- 
            # send(value, to=self.recipient)
            # send(self.deposit - value, to=self.sender)
            # self.destruct()
            print('Success')

```
### How Alice and Bob can use this contract

(1) Let’s create two wallets. One for Alice and one for Bob.

```python
# Create Bob's account
priv = keccak('Bob')
addr = privtoaddr(priv)
pub = to_checksum_address(addr)
bob = {'pub':pub, 'priv':priv}
```
```python
# Create Alice's account
priv = keccak('Alice')
addr = privtoaddr(priv)
pub = to_checksum_address(addr)
alice = {'pub':pub, 'priv':priv}
```
First Bob created the state channel contract and deposits 1 ETH.

```python
# Bob opens the state channel and (pseudo-code) deposits 1 ETH
channel = Channel(sender=bob['pub'], recipient=alice['pub'], deposit=1)
```
Bob then needs to create and sign his first payment message to Alice. Alice and Bob have agreed upon a payment amount of 0.1 ETH per task. He then hashes this amount along with the contract address.

```python
# Payment per task
value = '0.1'
# Message hash (using the Python channel object's hash for its address)
msg_hash = keccak(str(channel.__hash__()) + value)
# These values represent the signed message
v, r, s = ecsign(msg_hash, bob['priv'])
```
He then sends the hashed message along with the signature of the hashed message to Alice.
```python
# Bob sends this to Alice
from_bob = {
    'v':v,
    'r':r,
    's':s,
    'h':msg_hash,
}
```
When Alice receives this message, she can double check that she will be able to cash it in. All that is required for her to do this is to make sure that the signature belongs to Bob, and that the message hash is their agreed upon value hashed together with the contract address.
```python
# Alice can verify (offchain) that to make sure bob isn't sending her junk:
bobs_promised_value = '0.1'
hash_contains_correct_value = keccak(str(channel.__hash__()) + bobs_promised_value) == from_bob['h']
signer_is_bob = ecrecover(**from_bob) == bob['pub']
```
If this checks out Alice can save this data somewhere safe and continue working for Bob. When she decides to cash out she creates her own message hash (with the promised value from Bob's most recent data sent to her).
```python
# What Alice needs to compute
bobs_promised_value = '0.1'
msg_hash = keccak(str(channel.__hash__()) + bobs_promised_value)
v, r, s = ecsign(msg_hash, alice['priv'])
```
She then needs to make two transactions to the Contract. The order of these transactions does not matter. In this tutorial she submits the values from Bob first.
```python
# Alice submits Bob's message hash and signature
channel.close_channel(
    from_bob['h'], 
    from_bob['v'], 
    from_bob['r'], 
    from_bob['s'], 
    bobs_promised_value, 
)
```
The way the contract is set up, the funds cannot be sent unless both signatures are provided. So Alice then submits her own message hash and signature.
```python3
# Alice submits her own values
channel.close_channel(
    msg_hash, 
    v, 
    r, 
    s, 
    bobs_promised_value, 
)
```
When she does this, her total payments are sent to her, all remaining funds in the contract are sent back to Bob, and the channel is closed.

And that's it! For more information on edge cases in which Bob and Alice actively try to cheat each other and how this contract prevents it, see Matthew's tutorial above. Thanks for reading!
