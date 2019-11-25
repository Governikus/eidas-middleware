This is the second version of the dvca connection configurator.

This version will add the newest CSCA root certificate (05/2019) to your POSeIDAS.xml.
The certificate will replace the current Master- and Defectlist Signer certificates, which will be outdated soon.
By using the root certificate, the Master- and Defectlist Trust Anchors do not need to be replaced every year.

Run this tool only in your productive environment! Do not run this on test environments!

How to use dvca-connection-configurator-v2:
1. Backup your POSeIDAS.xml
	The POSeIDAS.xml can be found in the "/config"-folder of your eidas-middleware.
2. Either copy the dvca-connection-configurator-v2.jar into the "/config"-folder or copy the POSeIDAS.xml into the same folder as dvca-connection-configurator-v2.jar.
3. Run JAR from command line and follow the instructions.

	EXAMPLE:
	java -jar dvca-connection-configurator-v2.jar

		This software will update the Master- and Defectlist Trust Anchor of your productive eidas-middleware.
        Run it in the same folder as your POSeIDAS.xml .
        BACKUP YOUR POSeIDAS.xml BEFOREHAND.
        Continue? (y/N): y
		Done!

4. If you copied your POSeIDAS.xml out of the "/config"-folder, copy it back now.
5. Run eIDAS Middleware and log into the admin interface. Click on "Renew Master and Defect List".

In case of problems or errors contact our support at: eidas-middleware@governikus.de
