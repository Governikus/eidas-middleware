#!/bin/bash
if [ ! $# -eq 1 ]
  then
    echo "Exactly one argument needed to specify the version, e.g. ./create-vm.sh SNAPSHOT"
    exit 1
fi

echo "Using Version $1"

# create resource folder
echo "Creating resource folder"
mkdir resources

# copy resources from doc to packer
echo "Copying resources"
cp ../doc/source/chapter/POSeIDAS_PRODUCTION.xml resources
cp ../doc/source/chapter/POSeIDAS_TESTING.xml resources
cp ../doc/source/chapter/eidasmiddleware.properties resources
cp ../doc/source/chapter/application.properties resources
cp eidas-middleware.service resources
cp iptables resources
cp sources.list resources

# copy jar to packer
echo "Copying JARs with version $1"
if [ $1 = "SNAPSHOT" ]; then
    BASEVERSION=$(wget -qO- --header="Accept: application/json" "http://gzrepository/nexus/service/local/artifact/maven/resolve?g=de.governikus.eumw&a=eidas-middleware&v=LATEST&r=snapshots" | python -c "import sys, json; print json.load(sys.stdin)['data']['baseVersion']")
    wget -P resources --content-disposition "http://gzrepository/nexus/service/local/artifact/maven/content?r=snapshots&v=LATEST&g=de.governikus.eumw&a=eidas-middleware"
    wget -P resources --content-disposition "http://gzrepository/nexus/service/local/artifact/maven/content?r=snapshots&v=LATEST&g=de.governikus.eumw&a=password-generator"
    wget -P resources --content-disposition "http://gzrepository/nexus/service/local/artifact/maven/content?r=snapshots&v=LATEST&g=de.governikus.eumw&a=configuration-wizard"
    mv resources/eidas-middleware*.jar resources/eidas-middleware-${BASEVERSION}.jar
    mv resources/password-generator*.jar resources/password-generator-${BASEVERSION}.jar
    mv resources/configuration-wizard*.jar resources/configuration-wizard-${BASEVERSION}.jar
    export VERSION=$BASEVERSION
else
    wget -P resources --content-disposition "http://gzrepository/nexus/service/local/artifact/maven/content?r=releases&v=$1&g=de.governikus.eumw&a=eidas-middleware"
    wget -P resources --content-disposition "http://gzrepository/nexus/service/local/artifact/maven/content?r=releases&v=$1&g=de.governikus.eumw&a=password-generator"
    wget -P resources --content-disposition "http://gzrepository/nexus/service/local/artifact/maven/content?r=releases&v=$1&g=de.governikus.eumw&a=configuration-wizard"
    export VERSION=$1
fi

# execute packer
echo "Executing packer"
if ! packer build -color=false eidasmw_appliance.json; then
    echo "PACKER FAILED"
    exit 1
fi

# cleanup
echo "Cleanup"
rm -r resources
rm -r packer_cache
