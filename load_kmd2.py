import imp
import marshal
import sys
from engine.kavcore import k2rsa, k2kmdfile

pu= k2rsa.read_key('engine/plugins/key.pkr')
k= k2kmdfile.KMD('dummy.kmd', pu)

code=marshal.loads(k.body[8:])
module=imp.new_module('dummy')
exec(code, module.__dict__)
sys.modules['dummy']=module

print(dir(module))