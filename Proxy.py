# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re

# 1MB buffer size
BUFFER_SIZE = 1000000

# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
  # Create a server socket
  # ~~~~ INSERT CODE ~~~~
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # ~~~~ END CODE INSERT ~~~~
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  # ~~~~ INSERT CODE ~~~~
  server_socket.bind((proxyHost, proxyPort))
  print("Proxy server is running on " + proxyHost + ":" + str(proxyPort))
  # ~~~~ END CODE INSERT ~~~~
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  # ~~~~ INSERT CODE ~~~~
  server_socket.listen(5)
  print("Listening on port " + str(proxyPort))
  # ~~~~ END CODE INSERT ~~~~
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None

  # Accept connection from client and store in the clientSocket
  try:
    # ~~~~ INSERT CODE ~~~~
    clientSocket, addr = server_socket.accept()
    # ~~~~ END CODE INSERT ~~~~
    print ('Received a connection')
  except:
    print ('Failed to accept connection')
    sys.exit()

  # Get HTTP request from client
  # and store it in the variable: message_bytes
  # ~~~~ INSERT CODE ~~~~
  message_bytes = clientSocket.recv(BUFFER_SIZE)
  # ~~~~ END CODE INSERT ~~~~
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
  requestParts = message.split()
  method = requestParts[0]
  URI = requestParts[1]
  version = requestParts[2]

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  # Get the requested resource from URI
  # Remove http protocol from the URI
  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

  # Remove parent directory changes - security
  URI = URI.replace('/..', '')

  # Split hostname from resource name
  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'

  if len(resourceParts) == 2:
    # Resource is absolute URI with hostname and resource
    resource = resource + resourceParts[1]

  print ('Requested Resource:\t' + resource)

  # Check if resource is in cache
  try:
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation = cacheLocation + 'default'

    print ('Cache location:\t\t' + cacheLocation)

    fileExists = os.path.isfile(cacheLocation)
    
    # Check wether the file is currently in the cache
    cacheFile = open(cacheLocation, "r")
    cacheData = cacheFile.readlines()

    print ('Cache hit! Loading from cache file: ' + cacheLocation)
    # ProxyServer finds a cache hit
    # Send back response to client 
    # ~~~~ INSERT CODE ~~~~
    clientSocket.sendall("HTTP/1.1 200 OK\r\n") 
    clientSocket.sendall("Content-Type: text/html\r\n".encode("utf-8"))  # Content-Type header is nessary
    clientSocket.sendall("Content-Length: " + str(len(cacheData)) + "\r\n".encode("utf-8"))
    clientSocket.sendall("Connection: close\r\n".encode("utf-8"))  # Connection header is nessary
    clientSocket.sendall("\r\n")
    
    for data in cacheData:
      clientSocket.sendall(data.encode("utf-8"))
    # ~~~~ END CODE INSERT ~~~~
    cacheFile.close()
    print ('Sent to the client:')
    print ('> ' + cacheData)
  except:
    # cache miss.  Get resource from origin server
    originServerSocket = None
    # Create a socket to connect to origin server
    # and store in originServerSocket
    # ~~~~ INSERT CODE ~~~~
    originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ~~~~ END CODE INSERT ~~~~

    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server
      # ~~~~ INSERT CODE ~~~~
      originServerSocket.connect((address, 80))  # Port 80 is the default port for HTTP, not 8080!!!
      # ~~~~ END CODE INSERT ~~~~
      print ('Connected to origin Server')

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      # ~~~~ INSERT CODE ~~~~
      originServerRequest = method + ' ' + resource + ' ' + version
      originServerRequestHeader = 'Host: ' + hostname
      print("Origin server request: " + originServerRequest)
      print("Origin server request header: " + originServerRequestHeader)
      # ~~~~ END CODE INSERT ~~~~

      # Construct the request to send to the origin server
      request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'

      # Request the web resource from origin server
      print ('Forwarding request to origin server:')
      for line in request.split('\r\n'):
        print ('> ' + line)

      try:
        originServerSocket.sendall(request.encode())
      except socket.error:
        print ('Forward request to origin failed')
        sys.exit()

      print('Request sent to origin server\n')

      # Get the response from the origin server
      # ~~~~ INSERT CODE ~~~~
      response = originServerSocket.recv(BUFFER_SIZE)
      print("Response received from origin server")
      # ~~~~ END CODE INSERT ~~~~

      # Send the response to the client
      # ~~~~ INSERT CODE ~~~~
      clientSocket.sendall(response)
      # ~~~~ END CODE INSERT ~~~~

      # Create a new file in the cache for the requested file.
      cacheDir, file = os.path.split(cacheLocation)
      print ('cached directory ' + cacheDir)
      if not os.path.exists(cacheDir):
        os.makedirs(cacheDir)
      cacheFile = open(cacheLocation, 'wb')

      # Save origin server response in the cache file
      # ~~~~ INSERT CODE ~~~~
      try:
        sanitized_path = re.sub(r'[?&:<>|*]', '_', cacheLocation)
        with open(sanitized_path, 'wb') as cacheFile:
          cacheFile.write(response)

        print ("Response saved to cache file")
      
      except OSError as err:
        print("Failed to save response to cache file: " + sanitized_path + " details: " + {err.strerror})
      # ~~~~ END CODE INSERT ~~~~
      cacheFile.close()
      print ('cache file closed')

      # finished communicating with origin server - shutdown socket writes
      print ('origin response received. Closing sockets')
      originServerSocket.close()
       
      clientSocket.shutdown(socket.SHUT_WR)
      print ('client socket shutdown for writing')
    except OSError as err:
      print ('origin server request failed. ' + err.strerror)

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')
