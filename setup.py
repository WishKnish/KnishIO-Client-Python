import re
import sys
import pathlib
from setuptools import find_packages, setup

if sys.version_info < (3, 11, 0):
    raise RuntimeError("KnishIOClient requires Python 3.11.0+")

txt = (pathlib.Path(__file__).parent / 'knishioclient' / '__init__.py').read_text('utf-8')

try:
    version = re.findall(r"^__version__ = '([^']+)'\r?$", txt, re.M)[0]
except IndexError:
    raise RuntimeError('Unable to determine version.')

setup(name='knishioclient',
      version=version,
      description='Knish.IO Python API Client',
      long_description=open("README.md", encoding='utf-8').read(),
      long_description_content_type="text/markdown",
      classifiers=[
          'Development Status :: 2 - Pre-Alpha',
          'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
          'Programming Language :: Python :: 3 :: Only',
          'Programming Language :: Python :: 3.11',
          'Programming Language :: Python :: 3.12',
          'Programming Language :: Python :: 3.13',
          'Topic :: Utilities',
      ],
      keywords=['wishknish', 'knishio', 'blockchain', 'dag', 'client'],
      platforms='all',
      python_requires='>=3.6.0',
      url='https://github.com/WishKnish/KnishIO-Client-Python',
      project_urls={
          'Homepage': 'https://knish.io',
          'GitHub: issues': 'https://github.com/WishKnish/KnishIO/issues',
          'GitHub: wiki': 'https://github.com/WishKnish/KnishIO/wiki',
          'GitHub: source': 'https://github.com/WishKnish/KnishIO',
          'Docs': 'https://docs.knish.io'
      },
      author='Yuri Kizilov',
      author_email='y.kizilov.sev@yandex.ru',
      license='LICENSE',
      packages=find_packages(),
      zip_safe=False,
      include_package_data=True,
      install_requires=open("requirements.txt").readlines()
      )
