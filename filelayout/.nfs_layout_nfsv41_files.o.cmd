savedcmd_fs/nfs/filelayout/nfs_layout_nfsv41_files.o := ld -m elf_x86_64 -z noexecstack --no-warn-rwx-segments   -r -o fs/nfs/filelayout/nfs_layout_nfsv41_files.o @fs/nfs/filelayout/nfs_layout_nfsv41_files.mod  ; ./tools/objtool/objtool --hacks=jump_label --hacks=noinstr --hacks=skylake --ibt --orc --retpoline --rethunk --sls --static-call --uaccess --prefix=16  --link  --module fs/nfs/filelayout/nfs_layout_nfsv41_files.o

fs/nfs/filelayout/nfs_layout_nfsv41_files.o: $(wildcard ./tools/objtool/objtool)
