# wine-doom
## Patched WINE BCrypt dll to run DOOM (2016)

irc: freenode.net #doom-wine

http://steamcommunity.com/app/379720/discussions/0/152391995402132325/


### Note

## You need to block doom servers or the game will hand due to bug in winhttp (saves and profiles should still work)
```
127.0.0.1 dfw-gobbler.doom.amok.systems
127.0.0.1 services.bethesda.net
```
## or you can try to use native winhttp

Decrypt/Encrypt uses standart PKCS #7 padding (when flag is set).
I'm not sure if that's correct, but it works with DooM.

Feel free to modify / send patches to wine / etc.

### How to build


1. Grab a copy of wine or wine-patched sources
2. Apply configure.patch
3. Run autoconf && autoheader
4. copy dlls and include folders from this repo
5. install libgcrypt development files (-dev/-devel/etc.)
6. configure
7. build

### You can run whole new wine or rename resulting lib and use wine dll redirection https://github.com/wine-compholio/wine-staging/wiki/DLL-Redirects


### ---
Thanks to https://github.com/thevoidnn/wine20-bcrypt-doom for initial implementaion






