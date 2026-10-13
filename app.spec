from PyInstaller.utils.hooks import collect_submodules
hidden = collect_submodules('ctf_forge')
a = Analysis(['main.py'], pathex=['src'], binaries=[], datas=[], hiddenimports=hidden, hookspath=[], hooksconfig={}, runtime_hooks=[], excludes=[], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='CTF-Forge', debug=False, bootloader_ignore_signals=False, strip=False, upx=True, console=False)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=True, name='CTF-Forge')
