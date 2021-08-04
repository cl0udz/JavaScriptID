import sys, base64

secrets = sys.argv[1]

print("Input: ", base64.b64encode(secrets.encode('ascii')))
