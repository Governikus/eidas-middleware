The TLS certificates of the productive authorization CA will expire in the near future.
To help you with the necessary changes to your configuration we offer you this tool.
It will automatically configure your eIDAS Middleware in order to keep its connection to the authorization CA.
More precisely it swaps the deprecated certificates and URIs in your POSeIDAS.xml for the latest ones.(Status 25.04.2019)

This is only necessary for your productive environment! Do not run this on test environments!


How to use dvca-connection-configurator:
1. Backup your POSeIDAS.xml
	The POSeIDAS.xml can be found in the "/config"-folder of your eidas-middleware.
2. Either copy the dvca-connection-configurator.jar into the "/config"-folder or copy the POSeIDAS.xml into the same folder as dvca-connection-configurator.jar.
3. Prepare/find your client certificate for SSL connection provided by the BSI. You should have received this certificate along with this tool.
4. Run JAR from command line and follow instructions.

	EXAMPLE:
	java -jar dvca-connection-configurator.jar

		This software will configure your productive eidas-middleware to connect to the D-Trust DVCA.
		Run it in the same folder as your POSeIDAS.xml.
		BACKUP YOUR POSeIDAS.xml BEFOREHAND.
		Continue? (y/N): y
		Enter the path to your client certificate:D:\clientCertificate.der
		Done!

5. If you copied your POSeIDAS.xml out of the "/config"-folder, copy it back now.
6. Run eIDAS Middleware and log into the admin interface. Check the connection with the "Check connection"-button. If it works click "Renew CVC"-button and after that the "Renew Black List"-button. If it worked, everything is configured correctly.

In case of problems or errors contact our support at: eidas-middleware@governikus.de