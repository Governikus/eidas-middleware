To send an eIDAS Request, open http://localhost:8080/NewRequesterServlet in your browser.

The following properties are required for the application.properties file:

# URL where the eIDAS Middleware is deployed
middleware.samlreceiverurl=

# Certificate to verify the signature of the eIDAS responses
middleware.signature.certificate=

# Keystore to sign the outgoing eIDAS requests
demo.signature.keystore=

# Alias for that key
demo.signature.alias=

# Pin for that keystore and entry
demo.signature.pin=

# The port the application should listen on.
server.port=8080
