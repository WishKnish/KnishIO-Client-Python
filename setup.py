import re
import shutil
import sys
import pathlib
from setuptools import find_packages, setup
from setuptools.command.build_py import build_py

if sys.version_info < (3, 11, 0):
    raise RuntimeError("KnishIOClient requires Python 3.11.0+")

txt = (pathlib.Path(__file__).parent / 'knishioclient' / '__init__.py').read_text('utf-8')

try:
    version = re.findall(r"^__version__ = '([^']+)'\r?$", txt, re.M)[0]
except IndexError:
    raise RuntimeError('Unable to determine version.')

BRIDGE_SOURCE = pathlib.Path(__file__).parent / 'bin'
BRIDGE_FILES = ('noble-mlkem-bridge.js', 'package.json', 'package-lock.json')


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
      cmdclass={'build_py': BuildPyWithBridge},
      )
