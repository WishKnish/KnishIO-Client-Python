import json
import os
import re
import shutil
import sys
import pathlib
from setuptools import find_packages, setup
from setuptools.command.build_py import build_py
from setuptools.command.bdist_wheel import bdist_wheel
from setuptools.dist import Distribution

if sys.version_info < (3, 11, 0):
    raise RuntimeError("KnishIOClient requires Python 3.11.0+")

txt = (pathlib.Path(__file__).parent / 'knishioclient' / '__init__.py').read_text('utf-8')

try:
    version = re.findall(r"^__version__ = '([^']+)'\r?$", txt, re.M)[0]
except IndexError:
    raise RuntimeError('Unable to determine version.')

BRIDGE_SOURCE = pathlib.Path(__file__).parent / 'bin'
BRIDGE_FILES = ('noble-mlkem-bridge.js', 'package.json', 'package-lock.json')

# Platform wheels: KNISHIO_KCORE_TARGET=<target> bundles the libkcore that
# `python scripts/fetch_kcore.py --target <target>` put in knishioclient/_kcore/, and tags the
# wheel py3-none-<platform>. Unset, the build is the pure py3-none-any wheel (and the sdist),
# which never carries a library and falls back to pure Python and the Node bridge.
KCORE_TARGET = os.environ.get('KNISHIO_KCORE_TARGET', '')
KCORE_SOURCE = pathlib.Path(__file__).parent / 'knishioclient' / '_kcore'
KCORE_PIN = None
if KCORE_TARGET:
    pins = json.loads((pathlib.Path(__file__).parent / 'scripts' / 'kcore-pins.json').read_text('utf-8'))
    KCORE_PIN = pins['targets'].get(KCORE_TARGET)
    if KCORE_PIN is None:
        raise RuntimeError(f'unknown KNISHIO_KCORE_TARGET {KCORE_TARGET}')


class BuildPyWithBridge(build_py):
    """Ship the ML-KEM bridge inside the package, as ``knishioclient/bin/``.

    ``knishioclient.libraries.NobleMLKEMBridge`` runs ``noble-mlkem-bridge.js`` with Node and
    loads ``@noble/post-quantum`` from the ``node_modules`` beside it. Both live in the
    repository's ``bin/``, outside the package, so ``find_packages()`` alone shipped neither and
    every installed copy failed with "Noble ML-KEM bridge script not found". An installed
    bridge finds itself under ``site-packages/knishioclient/bin/``. Install the pinned modules
    with ``npm ci`` in ``bin/`` before building; the build refuses to run without them.
    """

    def run(self):
        # A library left in build/ by an earlier target must never reach this wheel.
        stale = pathlib.Path(self.build_lib) / 'knishioclient' / '_kcore'
        if stale.exists():
            shutil.rmtree(stale)
        super().run()
        noble = BRIDGE_SOURCE / 'node_modules' / '@noble'
        if not (noble / 'post-quantum' / 'package.json').is_file():
            raise RuntimeError(
                'bin/node_modules/@noble/post-quantum is missing: run `npm ci` in bin/ before '
                'building, or the wheel ships without its ML-KEM bridge.')
        target = pathlib.Path(self.build_lib) / 'knishioclient' / 'bin'
        target.mkdir(parents=True, exist_ok=True)
        for name in BRIDGE_FILES:
            shutil.copy2(BRIDGE_SOURCE / name, target / name)
        shutil.copytree(noble, target / 'node_modules' / '@noble', dirs_exist_ok=True)
        if KCORE_PIN is not None:
            marker = KCORE_SOURCE / 'TARGET'
            library = KCORE_SOURCE / KCORE_PIN['name']
            if not marker.is_file() or marker.read_text('utf-8').strip() != KCORE_TARGET or not library.is_file():
                raise RuntimeError(f'run scripts/fetch_kcore.py --target {KCORE_TARGET} first')
            stale.mkdir(parents=True)
            shutil.copy2(library, stale / KCORE_PIN['name'])


class KcoreDistribution(Distribution):
    """With libkcore bundled the wheel is platform-specific: has_ext_modules() makes setuptools
    build into platlib and bdist_wheel set Root-Is-Purelib: false (no .data/purelib split)."""

    def has_ext_modules(self):
        return KCORE_PIN is not None


class BdistWheelKcore(bdist_wheel):
    """Tags a wheel that bundles libkcore py3-none-<platform>: the library is loaded through
    cffi's ABI mode, so it is independent of the CPython version and ABI."""

    def get_tag(self):
        if KCORE_PIN is not None:
            return 'py3', 'none', KCORE_PIN['wheel_tag']
        return super().get_tag()


setup(name='knishioclient',
      version=version,
      description='Knish.IO Python API Client',
      long_description=open("README.md", encoding='utf-8').read(),
      long_description_content_type="text/markdown",
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
          'Programming Language :: Python :: 3 :: Only',
          'Programming Language :: Python :: 3.11',
          'Programming Language :: Python :: 3.12',
          'Programming Language :: Python :: 3.13',
          'Topic :: Utilities',
      ],
      keywords=['wishknish', 'knishio', 'blockchain', 'dag', 'client'],
      platforms='all',
      python_requires='>=3.11',
      url='https://github.com/WishKnish/KnishIO-Client-Python',
      project_urls={
          'Homepage': 'https://knish.io',
          'GitHub: issues': 'https://github.com/WishKnish/KnishIO/issues',
          'GitHub: wiki': 'https://github.com/WishKnish/KnishIO/wiki',
          'GitHub: source': 'https://github.com/WishKnish/KnishIO',
          'Docs': 'https://docs.knish.io'
      },
      author='Eugene Teplitsky',
      author_email='eugene@wishknish.com',
      license='GPL-3.0-or-later',
      # `tests` has an __init__.py, so a bare find_packages() ships it as a TOP-LEVEL
      # package and puts `tests` on every consumer's import path, where it can shadow
      # their own. Exclude it explicitly; PyPI versions cannot be replaced once published.
      packages=find_packages(exclude=['tests', 'tests.*']),
      zip_safe=False,
      include_package_data=True,
      install_requires=open("requirements.txt").readlines(),
      distclass=KcoreDistribution,
      cmdclass={'build_py': BuildPyWithBridge, 'bdist_wheel': BdistWheelKcore},
      )
