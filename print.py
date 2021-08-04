import sys, base64

secrets = sys.argb[1]

print("Input: ", base64.b64encode(secrets.encode('ascii')))
