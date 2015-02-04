# The actual Invoke-Shellcode has moved to Invoke--Shellcode.ps1.
# This was done to make a point that you have no security sense
# if you think it's okay to blindly download/exec code directly
# from a GitHub repo you don't control. This will undoubedtly break
# many scripts that have this path hardcoded. If you don't like it,
# fork PowerSploit and host it yourself.

throw 'Something terrible may have just happened and you have no idea what because you just arbitrarily download crap from the Internet and execute it.'