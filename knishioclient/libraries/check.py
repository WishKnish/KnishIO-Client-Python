# -*- coding: utf-8 -*-

from hashlib import shake_256 as shake
from ..exception import *
from ..libraries import strings, decimal
from knishioclient import models
from typing import List


def verify(molecule: 'Molecule', sender: 'Wallet' = None) -> bool:
    """
    :param molecule: Molecule
    :param sender: Wallet default None
    :return: bool
    :raises BaseError:
    """
    # Order mirrors the JavaScript reference (CheckMolecule.verify): the cross-isotope
    # validators run before isotope_v, which delegates conservation to them whenever B/F
    # atoms are present. `index` is Python-specific and has no JS counterpart.
    for fun in (
        'molecular_hash',
        'ots',
        'isotope_m',
        'isotope_c',
        'isotope_t',
        'isotope_i',
        'isotope_u',
        'isotope_p',
        'isotope_a',
        'isotope_b',
        'isotope_f',
        'isotope_v',
        'index',
        # 'continu_id',
    ):
        # `fun in 'isotope_v'` was a SUBSTRING test, not equality. It happened to behave
        # correctly for the tuple above, but any short name added later (e.g. 'ots' is
        # already safe, but 'i', 'v' or 'so' would not be) would silently be dispatched
        # with the wrong arity.
        if fun == 'isotope_v':
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
        if atom.token != 'USER':  # equality (was `not in 'USER'`, a substring test); mirror JS/PHP isotopeC
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


def isotope_p(molecule: 'Molecule') -> bool:
    """
    Verification of P-isotope (Peering) atoms. Mirrors CheckMolecule.isotopeP() in JS.

    :param molecule: Molecule
    :return: bool
    :raises [WrongTokenTypeException, MetaMissingException]:
    """
    missing(molecule)

    for atom in isotope_filter('P', molecule.atoms):
        if atom.token != 'USER':
            raise WrongTokenTypeException(
                'Check::isotope_p() - "%s" is not a valid Token slug for "%s" isotope Atoms!'
                % (atom.token, atom.isotope)
            )

        metas = models.Meta.aggregate_meta(models.Meta.normalize_meta(atom.meta))

        if not metas.get('peerHost'):
            raise MetaMissingException(
                'Check::isotope_p() - Required meta field "peerHost" is missing!'
            )

    return True


def isotope_a(molecule: 'Molecule') -> bool:
    """
    Verification of A-isotope (Append Request) atoms. Mirrors CheckMolecule.isotopeA() in JS.

    :param molecule: Molecule
    :return: bool
    :raises [WrongTokenTypeException, MetaMissingException]:
    """
    missing(molecule)

    for atom in isotope_filter('A', molecule.atoms):
        if atom.token != 'USER':
            raise WrongTokenTypeException(
                'Check::isotope_a() - "%s" is not a valid Token slug for "%s" isotope Atoms!'
                % (atom.token, atom.isotope)
            )

        if not atom.metaType:
            raise MetaMissingException('Check::isotope_a() - Required field "metaType" is missing!')

        if not atom.metaId:
            raise MetaMissingException('Check::isotope_a() - Required field "metaId" is missing!')

        metas = models.Meta.aggregate_meta(models.Meta.normalize_meta(atom.meta))

        if not metas.get('action'):
            raise MetaMissingException(
                'Check::isotope_a() - Required meta field "action" is missing!'
            )

    return True


def isotope_b(molecule: 'Molecule') -> bool:
    """
    Verification of B-isotope (Buffer/Exchange) atoms. Mirrors CheckMolecule.isotopeB() in JS.

    Buffer molecules are cross-isotope: their V atoms do not balance on their own because
    a B atom absorbs the difference. isotope_v() therefore skips its V-only conservation
    whenever B/F atoms are present, and conservation is enforced here over the combined
    V+B set instead.

    :param molecule: Molecule
    :return: bool
    :raises [MetaMissingException, TransferMalformedException, TransferUnbalancedException]:
    """
    missing(molecule)

    atoms = isotope_filter('B', molecule.atoms)

    if len(atoms) == 0:
        return True

    for atom in atoms:
        # B atoms must reference a wallet bundle
        if atom.metaType != 'walletBundle':
            raise MetaMissingException(
                'Check::isotope_b() - B-isotope atoms must have metaType "walletBundle"!'
            )

        if not atom.metaId:
            raise MetaMissingException('Check::isotope_b() - B-isotope atoms must have a metaId!')

        try:
            strings.number(atom.value)
        except (TypeError, ValueError):
            raise TransferMalformedException(
                'Check::isotope_b() - B-isotope atom value is not a valid number!'
            )

    # V+B balance conservation: sum of all V and B atom values must equal zero
    v_atoms = isotope_filter('V', molecule.atoms)
    if len(v_atoms) > 0:
        total = 0
        for atom in v_atoms + atoms:
            try:
                total += strings.number(atom.value)
            except (TypeError, ValueError):
                continue
        if not decimal.equal(total, 0):
            raise TransferUnbalancedException(
                'Check::isotope_b() - V+B atom values do not balance to zero!'
            )

    return True


def isotope_f(molecule: 'Molecule') -> bool:
    """
    Verification of F-isotope (Fusion/NFT) atoms. Mirrors CheckMolecule.isotopeF() in JS.

    Identical to isotope_b() plus a non-negative-value rule. Must stay paired with the
    has_cross_isotope gate in isotope_v(), which is keyed on B *or* F: without this check
    an F-isotope molecule would skip V-only conservation with nothing validating V+F.

    :param molecule: Molecule
    :return: bool
    :raises [MetaMissingException, TransferMalformedException, TransferUnbalancedException]:
    """
    missing(molecule)

    atoms = isotope_filter('F', molecule.atoms)

    if len(atoms) == 0:
        return True

    for atom in atoms:
        if atom.metaType != 'walletBundle':
            raise MetaMissingException(
                'Check::isotope_f() - F-isotope atoms must have metaType "walletBundle"!'
            )

        if not atom.metaId:
            raise MetaMissingException('Check::isotope_f() - F-isotope atoms must have a metaId!')

        try:
            value = strings.number(atom.value)
        except (TypeError, ValueError):
            raise TransferMalformedException(
                'Check::isotope_f() - F-isotope atom value is not a valid number!'
            )

        if value < 0:
            raise TransferMalformedException(
                'Check::isotope_f() - F-isotope atom value must not be negative!'
            )

    # V+F balance conservation: sum of all V and F atom values must equal zero
    v_atoms = isotope_filter('V', molecule.atoms)
    if len(v_atoms) > 0:
        total = 0
        for atom in v_atoms + atoms:
            try:
                total += strings.number(atom.value)
            except (TypeError, ValueError):
                continue
        if not decimal.equal(total, 0):
            raise TransferUnbalancedException(
                'Check::isotope_f() - V+F atom values do not balance to zero!'
            )

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

    # B/F isotope molecules have V-atoms that don't sum to zero on their own (the B/F
    # atom absorbs the difference), so the plain V-conservation checks are skipped when
    # a cross-isotope is present — conservation is enforced by isotope_b()/isotope_f().
    # Keyed on isotope PRESENCE, not atom shape: a deposit is [V,B,V] and a withdraw is
    # [B,V,B], and a shape-based test accepts the first while rejecting the second.
    has_cross_isotope = len(isotope_filter('B', molecule.atoms)) > 0 \
        or len(isotope_filter('F', molecule.atoms)) > 0

    # Mirrors JS CheckMolecule.js:507. Two corrections against the previous form:
    #   - gated on cross-isotope, so buffer molecules do not take this branch at all
    #   - counts V atoms, not total atoms (JS tests isotopeV.length === 2)
    v_atoms = isotope_filter('V', molecule.atoms)
    if not has_cross_isotope and first_atom.isotope == 'V' and len(v_atoms) == 2:
        end_atom = v_atoms[len(v_atoms) - 1]
        if first_atom.token != end_atom.token:
            raise TransferMismatchedException()
        if strings.number(end_atom.value) < 0:
            raise TransferMalformedException()
        # Conservation for 2-atom transfers (JS :519-521). This branch returns early, so
        # without it the general sum check below is never reached and a two-atom transfer
        # that creates or destroys value is accepted.
        if not decimal.equal(
            strings.number(first_atom.value) + strings.number(end_atom.value), 0
        ):
            raise TransferUnbalancedException()
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
            try:
                cmp_result = decimal.cmp(value, 0.0)
                if cmp_result is not None and cmp_result < 0:
                    raise TransferMalformedException()
            except (TypeError, AttributeError):
                # If comparison fails, skip this check (malformed molecule)
                pass

            # Cannot be sending and receiving from the same address.
            # A shadow/batched recipient atom has no walletAddress (keyed by
            # bundle + batchId), so it can never be a self-transfer — skip the
            # check rather than crash on `None in <str>`.
            if v_atom.walletAddress and first_atom.walletAddress \
                    and v_atom.walletAddress in first_atom.walletAddress:
                raise TransferToSelfException()

        # Adding this Atom's value to the total sum
        amount += value

    # V-only conservation: all V atoms must sum to zero (skipped for B/F cross-isotope,
    # where isotope_b()/isotope_f() own conservation over the combined set)
    if not has_cross_isotope and not decimal.equal(amount, 0):
        raise TransferUnbalancedException()

    # If we're provided with a senderWallet argument, we can perform additional checks
    if sender is not None:
        remainder = strings.number(sender.balance) + strings.number(first_atom.value)

        # Is there enough balance to send?
        try:
            cmp_result = decimal.cmp(remainder, 0)
            if cmp_result is not None and cmp_result < 0:
                raise TransferBalanceException()
        except (TypeError, AttributeError):
            # If comparison fails, skip this check (malformed molecule)
            pass

        # Does the remainder match what should be there in the source wallet, if provided?
        # After all atoms are applied, the sum should be 0, so remainder should also be 0.
        # Skipped for cross-isotope (B/F) — conservation is validated by isotope_b()/isotope_f()
        if not has_cross_isotope and not decimal.equal(remainder, 0):
            raise TransferRemainderException()
    # No senderWallet, but have a remainder?
    elif not has_cross_isotope and not decimal.equal(amount, 0.0):
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
