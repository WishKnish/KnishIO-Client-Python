<div style="text-align:center">
  <img src="https://raw.githubusercontent.com/WishKnish/KnishIO-Technical-Whitepaper/master/KnishIO-Logo.png" alt="Knish.IO: Post-Blockchain Platform" />
</div>
<div style="text-align:center">info@wishknish.com | https://wishknish.com</div>

# Knish.IO Python Client SDK

This is the official Python implementation of the Knish.IO client SDK. Its purpose is to expose class libraries for building and signing Knish.IO Molecules, composing Atoms, generating Wallets, and much more.

## Installation

The SDK can be installed via pip:

```bash
pip install knishioclient
```

**Requirements:**
- Python 3.11 or higher
- Node.js 16 or higher (required for ML-KEM768 quantum-resistant cryptography)
- Virtual environment (recommended)
- Required packages: numpy, cryptography, libnacl, base58, pycryptodome, aiohttp

**Setup with virtual environment:**

```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the SDK
pip install knishioclient

# Or install from requirements.txt for development
pip install -r requirements.txt

# Install Node.js dependencies for ML-KEM768 bridge
cd bin
npm install
cd ..
```

After installation, import the SDK in your project:

```python
from knishioclient.client.KnishIOClient import KnishIOClient
from knishioclient.models import Wallet, Molecule, Atom
from knishioclient.libraries import crypto
```

## Basic Usage

The purpose of the Knish.IO SDK is to expose various ledger functions to new or existing applications.

There are two ways to take advantage of these functions:

1. The easy way: use the `KnishIOClient` wrapper class

2. The granular way: build `Atom` and `Molecule` instances and broadcast GraphQL messages yourself

This document will explain both ways.

## The Easy Way: KnishIOClient Wrapper

1. Include the wrapper class in your application code:
   ```python
   from knishioclient.client.KnishIOClient import KnishIOClient
   ```

2. Instantiate the class with your node URI:
   ```python
   client = KnishIOClient("http://localhost:8000/graphql")
   client.set_cell_slug("my-cell-slug")
   ```

3. Request authorization token from the node:
   ```python
   response = client.request_auth_token(secret)
   
   if response.success():
       # Authentication successful
       print("Authenticated successfully!")
   else:
       raise Exception(f"Authentication failed: {response.reason()}")
   ```

   (**Note:** The `secret` parameter can be a salted combination of username + password, a biometric hash, an existing user identifier from an external authentication process, for example)

4. Begin using `client` to trigger commands described below...

### KnishIOClient Methods

- Query metadata for a **Wallet Bundle**. Omit the `bundle_hash` parameter to query your own Wallet Bundle:
  ```python
  response = client.query_bundle(
      bundle_hash='c47e20f99df190e418f0cc5ddfa2791e9ccc4eb297cfa21bd317dc0f98313b1d'
  )
  
  if response.success():
      bundle_data = response.data()
      print(bundle_data)  # Raw Metadata
  ```

- Query metadata for a **Meta Asset**:

  ```python
  result = client.query_meta(
      meta_type='Vehicle',
      meta_id=None,  # Meta ID
      key='LicensePlate',
      value='1H17P',
      latest=True,  # Limit meta values to latest per key
      through_atom=True  # Optional, query through Atom (default: True)
  )

  print(result)  # Raw Metadata
  ```

- Writing new metadata for a **Meta Asset**:

  ```python
  response = client.create_meta(
      meta_type='Pokemon',
      meta_id='Charizard',
      metadata={
          'type': 'fire',
          'weaknesses': [
              'rock',
              'water',
              'electric'
          ],
          'immunities': [
              'ground',
          ],
          'hp': 78,
          'attack': 84,
      }
  )

  if response.success():
      # Do things!
      print("Metadata created successfully!")

  print(response.data())  # Raw response
  ```

- Query Wallets associated with a Wallet Bundle:

  ```python
  wallets = client.query_wallets(
      bundle_hash='c47e20f99df190e418f0cc5ddfa2791e9ccc4eb297cfa21bd317dc0f98313b1d',
      unspent=True  # Optional, limit results to unspent wallets
  )

  print(wallets)  # Raw response
  ```

- Declaring new **Wallets**:

  (**Note:** If Tokens are sent to undeclared Wallets, **Shadow Wallets** will be used (placeholder
  Wallets that can receive, but cannot send) to store tokens until they are claimed.)

  ```python
  response = client.create_wallet('FOO')  # Token Slug for the wallet we are declaring

  if response.success():
      # Do things!
      print("Wallet created successfully!")

  print(response.data())  # Raw response
  ```

- Issuing new **Tokens**:

  ```python
  response = client.create_token(
      token_slug='CRZY',  # Token slug (ticker symbol)
      initial_amount=100000000,  # Initial amount to issue
      meta={
          'name': 'CrazyCoin',  # Public name for the token
          'fungibility': 'fungible',  # Fungibility style (fungible / nonfungible / stackable)
          'supply': 'limited',  # Supply style (limited / replenishable)
          'decimals': 2  # Decimal places
      },
      units=[],  # Optional, for stackable tokens
      batch_id=None  # Optional, for stackable tokens
  )

  if response.success():
      # Do things!
      print("Token created successfully!")

  print(response.data())  # Raw response
  ```

- Transferring **Tokens** to other users:

  ```python
  response = client.transfer_token(
      wallet_object_or_bundle_hash='7bf38257401eb3b0f20cabf5e6cf3f14c76760386473b220d95fa1c38642b61d',  # Recipient's bundle hash
      token_slug='CRZY',  # Token slug
      amount=100,
      units=[],  # Optional, for stackable tokens
      batch_id=None  # Optional, for stackable tokens
  )

  if response.success():
      # Do things!
      print("Token transferred successfully!")

  print(response.data())  # Raw response
  ```

- Creating a new **Rule**:

  ```python
  response = client.create_rule(
      meta_type='MyMetaType',
      meta_id='MyMetaId',
      rule=[
          # Rule definition
      ],
      policy={}  # Optional policy object
  )

  if response.success():
      # Do things!
      print("Rule created successfully!")

  print(response.data())  # Raw response
  ```

- Querying **Atoms**:

  ```python
  response = client.query_atom(
      molecular_hash='hash',
      bundle_hash='bundle',
      isotope='V',
      token_slug='CRZY',
      latest=True,
      limit=15,
      offset=1
  )

  print(response.data())  # Raw response
  ```

- Working with **Buffer Tokens**:

  ```python
  # Deposit to buffer
  deposit_response = client.deposit_buffer_token(
      token_slug='CRZY',
      amount=100,
      trade_rates={
          'OTHER_TOKEN': 0.5
      }
  )

  # Withdraw from buffer
  withdraw_response = client.withdraw_buffer_token(
      token_slug='CRZY',
      amount=50
  )

  print([deposit_response.data(), withdraw_response.data()])  # Raw responses
  ```

- Getting client information:

  ```python
  # Note: Fingerprint methods may not be available in the Python SDK
  # Check client configuration and bundle information
  if client.has_secret():
      bundle = client.bundle()
      print(f"Client bundle: {bundle}")
  ```

## Advanced Usage: Working with Molecules

For more granular control, you can work directly with Molecules:

- Create a new Molecule:
  ```python
  from knishioclient.models import Molecule
  
  molecule = Molecule(
      secret=secret,
      source_wallet=source_wallet,
      remainder_wallet=remainder_wallet,
      cell_slug=cell_slug
  )
  ```

- Create a custom Mutation:
  ```python
  from knishioclient.mutation.MutationProposeMolecule import MutationProposeMolecule
  
  mutation = MutationProposeMolecule(client, molecule)
  ```

- Sign and check a Molecule:
  ```python
  molecule.sign()
  try:
      if molecule.check():
          print("Molecule validation passed!")
      else:
          print("Molecule validation failed!")
  except Exception as e:
      print(f"Molecule validation error: {e}")
  ```

- Execute a custom Query or Mutation:
  ```python
  response = client.execute_query(mutation)
  
  if response.success():
      print("Molecule executed successfully!")
  ```

## The Hard Way: DIY Everything

This method involves individually building Atoms and Molecules, triggering the signature and validation processes, and communicating the resulting signed Molecule mutation or Query to a Knish.IO node via GraphQL.

1. Include the relevant classes in your application code:
    ```python
    from knishioclient.models import Molecule, Wallet, Atom
    from knishioclient.libraries import crypto
    ```

2. Generate a 2048-symbol hexadecimal secret, either randomly, or via hashing login + password + salt, OAuth secret ID, biometric ID, or any other static value.

3. (optional) Initialize a signing wallet with:
   ```python
   wallet = Wallet(
       secret=secret,
       token=token_slug,
       position=custom_position,  # (optional) instantiate specific wallet instance vs. random
       characters=character_set  # (optional) override the character set used by the wallet
   )
   ```

   **WARNING 1:** If ContinuID is enabled on the node, you will need to use a specific wallet, and therefore will first need to query the node to retrieve the `position` for that wallet.

   **WARNING 2:** The Knish.IO protocol mandates that all C and M transactions be signed with a `USER` token wallet.

4. Build your molecule with:
   ```python
   molecule = Molecule(
       secret=secret,
       source_wallet=source_wallet,  # (optional) wallet for signing
       remainder_wallet=remainder_wallet,  # (optional) wallet to receive remainder tokens
       cell_slug=cell_slug  # (optional) used to point a transaction to a specific branch of the ledger
   )
   ```

5. Either use one of the shortcut methods provided by the `Molecule` class (which will build `Atom` instances for you), or create `Atom` instances yourself.

   DIY example:
    ```python
    # This example records a new Wallet on the ledger

    # Define metadata for our new wallet
    new_wallet_meta = {
        'address': new_wallet.address,
        'token': new_wallet.token,
        'bundle': new_wallet.bundle,
        'position': new_wallet.position,
        'batchId': new_wallet.batchId,
    }

    # Build the C isotope atom
    wallet_creation_atom = Atom(
        position=source_wallet.position,
        wallet_address=source_wallet.address,
        isotope='C',
        token=source_wallet.token,
        meta_type='wallet',
        meta_id=new_wallet.address,
        meta=new_wallet_meta,
        index=molecule.generate_index()
    )

    # Add the atom to our molecule
    molecule.add_atom(wallet_creation_atom)

    # Adding a ContinuID / remainder atom
    molecule.add_continu_id_atom()
    ```

   Molecule shortcut method example:
    ```python
    # This example commits metadata to some Meta Asset

    # Defining our metadata
    metadata = {
        'foo': 'Foo',
        'bar': 'Bar'
    }

    molecule.init_meta(
        meta=metadata,
        meta_type='MyMetaType',
        meta_id='MetaId123'
    )
    ```

6. Sign the molecule with the stored user secret:
    ```python
    molecule.sign()
    ```

7. Make sure everything checks out by verifying the molecule:
    ```python
    try:
        if molecule.check():
            # If we're validating a V isotope transaction,
            # add the source wallet as a parameter
            print("Molecule validation passed!")
        else:
            print("Molecule validation failed!")
    except Exception as e:
        print(f"Molecule check failed: {e}")
        # Handle the error
    ```

8. Broadcast the molecule to a Knish.IO node:
    ```python
    from knishioclient.mutation.MutationProposeMolecule import MutationProposeMolecule
    
    # Build our mutation object using the KnishIOClient wrapper
    mutation = MutationProposeMolecule(client, molecule)

    # Send the mutation to the node and get a response
    response = client.execute_query(mutation)
    ```

9. Inspect the response...
    ```python
    # For basic queries, we look at the data property:
    print(response.data())

    # For mutations, check if the molecule was accepted by the ledger:
    print("Success" if response.success() else "Failed")

    # We can also check the reason for rejection
    print(response.reason())

    # Some queries may also produce a payload, with additional data:
    print(response.payload())
    ```

   Payloads are provided by responses to the following queries:
    1. `QueryBalance` and `QueryContinuId` -> returns a `Wallet` instance
    2. `QueryWalletList` -> returns a list of `Wallet` instances
    3. `MutationProposeMolecule`, `MutationRequestAuthorization`, `MutationCreateIdentifier`, `MutationLinkIdentifier`, `MutationClaimShadowWallet`, `MutationCreateToken`, `MutationRequestTokens`, and `MutationTransferTokens` -> returns molecule metadata

## Getting Help

Knish.IO is under active development, and our team is ready to assist with integration questions. The best way to seek help is to stop by our [Telegram Support Channel](https://t.me/wishknish). You can also [send us a contact request](https://knish.io/contact) via our website.
