# Knish.IO Python Client
This is an experimental Python implementation of the Knish.IO API client. Its purpose is to expose class libraries for building and signing Knish.IO Molecules, composing Atoms (presently "A", "C", "M", "U", "I", "T" and "V" isotopes are supported), and generating Wallet addresses (public keys) and private keys as per the Knish.IO Technical Whitepaper.

# Getting Started
1. `pip install knishio-client-python`
2. Inside your application code, `from knishioclient.models import Molecule, Wallet`
3. Build a 2048-character user secret via your preferred methodology (random string?).
4. Initialize a wallet with `wallet = Wallet(secret, token)`

You can also specify a third, optional `position` argument represents the private key index (hexadecimal), and must NEVER be used more than once. It will be generated randmly if not provided.

A fourth argument, `salt_length`, helps tweak the length of the random `position`, if the parameter is not provided.

The `token` argument (string) is the slug for the token being transacted with. Knish.IO anticipates user's personal metadata being kept under the `USER` token.

# Building Your Molecule
1. Build your molecule with `molecule = Molecule(secret, source_wallet, remainder_wallet, cell_slug)` The `cell_slug` argument represents the slug for your Knish.IO cell. It's meant to segregate molecules of one use case from others. Leave it null if not sure.
2. For a "M"-type molecule, build your metadata as an array of objects, for example:
```python
data = [
  {
    'key': 'name',
    'value': 'foo'
  },
  {
    'key': 'email',
    'value': 'bar'
  },
  #...
]
```
or
```python
data = {
  'name': 'foo',
  'email': 'bar',
  #...
}
```
3. Initialize the molecule as "M"-type: `molecule.init_meta(data, meta_type, meta_id)` The `meta_type` and `meta_id` arguments represent a polymorphic key to whatever asset you are attaching this metadata to.
4. Sign the molecule with the user secret: `molecule.sign()`
5. Make sure everything checks out by verifying the molecule:
```python
from knishioclient.models import Molecule, Wallet

source_wallet = Wallet(secret, token)
remainder_wallet = Wallet(secret, token)

molecule = Molecule(secret, source_wallet, remainder_wallet, cell_slug)

molecule.init_meta(data, meta_type, meta_id)
molecule.sign()

if molecule.check():
  #...  Do stuff? Send the molecule to a Knish.IO node, maybe?
```

# Broadcasting
1. Knish.IO nodes use GraphQL to receive new molecules as a Mutation. The code for the mutation is as follows:
```
  mutation MoleculeMutation($molecule: MoleculeInput!) {
    ProposeMolecule(
      molecule: $molecule,
    ) {
      molecularHash,
      height,
      depth,
      status,
      reason,
      reasonPayload,
      createdAt,
      receivedAt,
      processedAt,
      broadcastedAt
    }
  }
```
2. Use your favorite GraphQL client to send the mutation to a Knish.IO node with the molecule you've signed as the only parameter.
3. The `status` field of the response will indicate whether the molecule was accepted or rejected, or if it's pending further processing. The `reason` and `reasonPayload` fields can help further diagnose and handle rejections.
