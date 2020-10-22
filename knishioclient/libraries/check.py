# -*- coding: utf-8 -*-

from hashlib import shake_256 as shake
from knishioclient.exception import *
from knishioclient.libraries import strings, decimal
from knishioclient import models
from typing import List


def verify(molecule: 'Molecule', sender: 'Wallet' = None) -> bool:
    """
    :param molecule: Molecule
    :param sender: Wallet default None
    :return: bool
    :raises BaseError:
    """
    for fun in (
        'molecular_hash',
        'ots',
        'isotope_m',
        'isotope_c',
        'isotope_v',
        'isotope_t',
        'isotope_i',
        'isotope_u',
        'index',
        # 'continu_id',
    ):
        if fun in 'isotope_v':
            globals()[fun](molecule, sender)
        else:
            globals()[fun](molecule)
    return True


def continu_id(molecule: 'Molecule') -> bool:
    """
    :param molecule: Molecule
    :return: bool
    :raise [AtomsMissingException, MolecularHashMissingException, AtomsMissingException]
    """
    missing(molecule)
    atom = molecule.atoms[0]
    if atom.token in 'USER' and len(isotope_filter('I', molecule.atoms)) < 1:
        raise AtomsMissingException()
    return True


def isotope_t(molecule: 'Molecule') -> bool:
    """
    :param molecule: Molecule
    :return: bool
    :raise [MetaMissingException, AtomIndexException, WrongTokenTypeException, MolecularHashMissingException,
     AtomsMissingException]
    """
    missing(molecule)

    for atom in isotope_filter('T', molecule.atoms):
        meta = models.Meta.aggregate_meta(models.Meta.normalize_meta(atom.meta))
        meta_type = (atom.metaType or '').lower()

        if meta_type in 'wallet':
            for key in ('position', 'bundle',):
                if key not in meta or meta[key] is None:
                    raise MetaMissingException('No or not defined %s in meta' % key)
        for key in ('token',):
            if key not in meta or meta[key] is None:
                raise MetaMissingException('No or not defined %s in meta' % key)
        if atom.token not in 'USER':
            raise WrongTokenTypeException('Invalid token name for %s isotope' % atom.isotope)
        if atom.index != 0:
            raise AtomIndexException('Invalid isotope "%s" index' % atom.isotope)
    return True


def isotope_c(molecule: 'Molecule') -> bool:
    """
    :param molecule: Molecule
    :return: bool
    :raise [AtomIndexException, WrongTokenTypeException, MolecularHashMissingException, AtomsMissingException]
    """
    missing(molecule)

    for atom in isotope_filter('C', molecule.atoms):
        if atom.token not in 'USER':
            raise WrongTokenTypeException('Invalid token name for %s isotope' % atom.isotope)
        if atom.index != 0:
            raise AtomIndexException('Invalid isotope "%s" index' % atom.isotope)
    return True


def isotope_i(molecule: 'Molecule') -> bool:
    """
    :param molecule: Molecule
    :return: bool
    :raise [AtomIndexException, WrongTokenTypeException, MolecularHashMissingException, AtomsMissingException]
    """
    missing(molecule)

    for atom in isotope_filter('I', molecule.atoms):
        if atom.token not in 'USER':
            raise WrongTokenTypeException('Invalid token name for %s isotope' % atom.isotope)
        if atom.index == 0:
            raise AtomIndexException('Invalid isotope "%s" index' % atom.isotope)
    return True


def isotope_u(molecule: 'Molecule') -> bool:
    """
    :param molecule: Molecule
    :return: bool
    :raise [AtomIndexException, MolecularHashMissingException, AtomsMissingException]
    """
    missing(molecule)

    for atom in isotope_filter('U', molecule.atoms):
        if atom.index != 0:
            raise AtomIndexException('Invalid isotope "%s" index' % atom.isotope)
    return True


def isotope_m(molecule: 'Molecule') -> bool:
    """
    :param molecule: Molecule
    :return: bool
    :raise [MetaMissingException, WrongTokenTypeException, MolecularHashMissingException, AtomsMissingException]
    """
    missing(molecule)

    for atom in isotope_filter('M', molecule.atoms):
        if len(atom.meta) < 1:
            raise MetaMissingException()
        if atom.token not in 'USER':
            raise WrongTokenTypeException('Invalid token name for %s isotope' % atom.isotope)

    return True


def isotope_v(molecule: 'Molecule', sender: 'Wallet' = None) -> bool:
    """
    Verification of V-isotope molecules checks to make sure that:
    1. we're sending and receiving the same token
    2. we're only subtracting on the first atom

    :param molecule: Molecule
    :param sender: Wallet default None
    :return: bool
    :raises [MolecularHashMissingException, AtomsMissingException, TransferMismatchedException, TransferToSelfException, TransferUnbalancedException, TransferBalanceException, TransferRemainderException]:
    """
    missing(molecule)

    # No isotopes "V" unnecessary and verification
    if len(isotope_filter('V', molecule.atoms)) == 0:
        return True

    # Grabbing the first atom
    # Looping through each V-isotope atom
    amount, value, first_atom = 0, 0, molecule.atoms[0]

    if first_atom.isotope in 'V' and len(molecule.atoms) == 2:
        end_atom = molecule.atoms[len(molecule.atoms) - 1]
        if first_atom.token not in end_atom.token:
            raise TransferMismatchedException()
        if strings.number(end_atom.value) < 0:
            raise TransferMalformedException()
        return True

    for index, v_atom in enumerate(molecule.atoms):

        #  Not V? Next...
        if 'V' != v_atom.isotope:
            continue

        # Making sure we're in integer land
        value = strings.number(v_atom.value)

        # Making sure all V atoms of the same token
        if v_atom.token not in first_atom.token:
            raise TransferMismatchedException()

        # Checking non-primary atoms
        if index > 0:

            # Negative V atom in a non-primary position?
            if decimal.cmp(strings.number(value), 0.0) < 0:
                raise TransferMalformedException()

            # Cannot be sending and receiving from the same address
            if v_atom.walletAddress in first_atom.walletAddress:
                raise TransferToSelfException()

        # Adding this Atom's value to the total sum
        amount += value

    # Does the total sum of all atoms equal the remainder atom's value? (all other atoms must add up to zero)
    if not decimal.equal(amount, value):
        raise TransferUnbalancedException()

    # If we're provided with a senderWallet argument, we can perform additional checks
    if sender is not None:
        remainder = strings.number(sender.balance) + strings.number(first_atom.value)

        # Is there enough balance to send?
        if decimal.cmp(remainder, 0) < 0:
            raise TransferBalanceException()

        # Does the remainder match what should be there in the source wallet, if provided?
        if not decimal.equal(remainder, amount):
            raise TransferRemainderException()
    # No senderWallet, but have a remainder?
    elif not decimal.equal(amount, 0.0):
        raise TransferRemainderException()

    # Looks like we passed all the tests!
    return True


def index(molecule: 'Molecule') -> bool:
    """
    :param molecule: Molecule
    :return: bool
    :raises [MolecularHashMissingException, AtomsMissingException, AtomIndexException]:
    """
    missing(molecule)

    if len([atom for atom in molecule.atoms if atom.index is None]) != 0:
        raise AtomIndexException()

    return True


def molecular_hash(molecule: 'Molecule') -> bool:
    """
    Verifies if the hash of all the atoms matches the molecular hash to ensure content has not been messed with

    :param molecule: Molecule
    :return: bool
    :raises [MolecularHashMissingException, AtomsMissingException, MolecularHashMismatchException]:
    """

    missing(molecule)

    if molecule.molecularHash != models.Atom.hash_atoms(molecule.atoms):
        raise MolecularHashMismatchException()

    return True


def ots(molecule: 'Molecule') -> bool:
    """
    This section describes the function DecodeOtsFragments(Om, Hm), which is used to transform a collection
    of signature fragments Om and a molecular hash Hm into a single-use wallet address to be matched against
    the sender’s address.

    :param molecule: Molecule
    :return: bool
    :raises [MolecularHashMissingException, AtomsMissingException, SignatureMalformedException, SignatureMismatchException]:
    """
    missing(molecule)

    # Determine first atom
    first_atom = molecule.atoms[0]
    # Rebuilding OTS out of all the atoms
    key = ''.join([atom.otsFragment for atom in molecule.atoms])

    # Wrong size? Maybe it's compressed
    if 2048 != len(key):
        # Attempt decompression
        key = strings.base64_to_hex(key)
        # Still wrong? That's a failure
        if 2048 != len(key):
            raise SignatureMalformedException()

    key_fragments = molecule.signature_fragments(key, False)

    # Absorb the hashed Kk into the sponge to receive the digest Dk
    sponge = shake()
    sponge.update(strings.encode(key_fragments))
    digest = sponge.hexdigest(1024)

    # Squeeze the sponge to retrieve a 128 byte (64 character) string that should match the sender’s
    # wallet address
    sponge = shake()
    sponge.update(strings.encode(digest))
    address = sponge.hexdigest(32)

    if address != first_atom.walletAddress:
        raise SignatureMismatchException()

    return True


def isotope_filter(isotope: str, atoms: List) -> List:
    """
    :param isotope: str
    :param atoms: List
    :return: List
    """
    return [atom for atom in atoms if isotope == atom.isotope]


def missing(molecule: 'Molecule') -> None:
    """
    :param molecule: Molecule
    """
    # No molecular hash?
    if molecule.molecularHash is None:
        raise MolecularHashMissingException()

    # Do we even have atoms?
    if len(molecule.atoms) < 1:
        raise AtomsMissingException()
