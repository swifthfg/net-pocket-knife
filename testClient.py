import socket
targetHost = "127.0.0.1"
targetPort = 9999

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((targetHost, targetPort))
client.send("ASDFADSFGG")
response = client.recv(4096)

print response