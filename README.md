# wine-doom
## Patched WINE BCrypt dll to run DOOM (2016)

irc: freenode.net #doom-wine
http://steamcommunity.com/app/379720/discussions/0/152391995402132325/


### Note

Decrypt/Encrypt still needs proper padding implementation.
It kinda works now, but can break.

### How to build


1. Grab a copy of wine or wine-patched sources
2. Apply configure.patch
3. copy dlls and include folders from this repo
4. install libgcrypt development files (-dev/-devel/etc.)
5. build

### You can run whole new wine or rename resulting lib and use wine dll redirection https://github.com/wine-compholio/wine-staging/wiki/DLL-Redirects


### ---
Thanks to https://github.com/thevoidnn/wine20-bcrypt-doom for initial implementaion






