from distutils.core import setup, Extension


setup(name='core',
      version='1.0',
      description='NOJ V2 JUDGE CORE',
      ext_modules = [
          Extension('core', ['judge_client.cc'])
      ]
     )
