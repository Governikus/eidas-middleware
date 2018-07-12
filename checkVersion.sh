#!/bin/bash
grep -rIn --color=auto --exclude-dir="target" --exclude-dir="_build"  --exclude-dir="\.idea" --exclude-dir="\.hg" --exclude-dir="\.settings" --exclude=\*.{iml,xsd,java,wsdl} --exclude=pom.xml --exclude=.hgtags "1\.0\." .
