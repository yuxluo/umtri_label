import builtins as _mod_builtins

__doc__ = None
__file__ = '/usr/local/lib/python3.7/dist-packages/bcrypt/_bcrypt.abi3.so'
__name__ = 'bcrypt._bcrypt'
__package__ = 'bcrypt'
ffi = _mod_builtins.CompiledFFI()
class lib(_mod_builtins.object):
    @staticmethod
    def bcrypt_hashpass():
        'int bcrypt_hashpass(char *, char *, char *, size_t);\n\nCFFI C function from _bcrypt.lib'
        pass
    
    @staticmethod
    def bcrypt_pbkdf():
        'int bcrypt_pbkdf(char *, size_t, uint8_t *, size_t, uint8_t *, size_t, unsigned int);\n\nCFFI C function from _bcrypt.lib'
        pass
    
    @staticmethod
    def encode_base64():
        'int encode_base64(char *, uint8_t *, size_t);\n\nCFFI C function from _bcrypt.lib'
        pass
    
    @staticmethod
    def timingsafe_bcmp():
        'int timingsafe_bcmp(void *, void *, size_t);\n\nCFFI C function from _bcrypt.lib'
        pass
    

