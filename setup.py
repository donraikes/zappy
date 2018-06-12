from setuptools import setup, find_packages

setup(name='zappy',
      version='0.1',
      description='An abstraction layer for the zaproxy python api',
      long_description='A simplified abstraction layer for the zaproxy python api',
      classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: GPLv3 License',
        'Programming Language :: Python :: 2.7',
        'Topic :: security :: proxy '
      ],
      keywords='security intercepting proxy zaproxy',
      url='http://github.com/donraikes/zappy.git',
      author='Donald Raikes',
      author_email='don.raikes@oracle.com',
      license='GPLv3',
      packages=find_packages(exclude=['test']),
      install_requires=[
      'django<2',
      'python-owasp-zap-v2.4'
      ],
      include_package_data=True,
      zip_safe=False)
