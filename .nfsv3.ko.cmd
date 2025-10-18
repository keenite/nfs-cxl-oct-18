savedcmd_fs/nfs/nfsv3.ko := ld -r -m elf_x86_64 -z noexecstack --no-warn-rwx-segments --build-id=sha1  -T scripts/module.lds -o fs/nfs/nfsv3.ko fs/nfs/nfsv3.o fs/nfs/nfsv3.mod.o;  true
