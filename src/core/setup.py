from distutils.core import setup, Extension

setup(name='sabo_core',
    version='1.0',
    description='sabo judge core',
    ext_modules = [
        Extension('sabo_core', ['sabo_core.c'])
    ]
)
