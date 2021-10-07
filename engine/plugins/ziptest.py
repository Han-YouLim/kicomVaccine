import zip
import mmap

k=zip.KavMain()
k.init('')

fp=open('dummy.zip', 'rb')
mm=mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
ff=k.format(mm, 'dummy.zip')
ff

flist=k.arclist('dummy.zip',ff)
flist

buf=k.unarc('arc_zip', 'dummy.zip', 'dummy.txt')
buf

mm.close()
fp.close()
k.uninit()