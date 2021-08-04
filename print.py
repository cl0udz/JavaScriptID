import sys, base64

print("Input: ", base64.b64encode(sys.argv[1].encode('ascii')))
