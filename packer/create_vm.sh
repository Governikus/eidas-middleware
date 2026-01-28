#!/bin/bash
if [ ! $# -eq 2 ]
  then
    echo "Exactly two arguments needed: version and path to OA template, e.g. ./create_vm.sh SNAPSHOT file:/path/to/ova"
    exit 1
fi

echo "Using Version $1"

# create resource folder
echo "Creating resource folder"
mkdir resources

# copy resources from doc to packer
echo "Copying resources"
cp ../doc/source/chapter/eIDAS_Middleware_configuration_prod.xml resources
cp ../doc/source/chapter/eIDAS_Middleware_configuration_test.xml resources
cp ../doc/source/chapter/application.properties resources
cp eidas-middleware.service resources
cp iptables resources
cp sources.list resources

# copy jar to packer
echo "Copying JARs with version $1"
export POM_VERSION=$1
if [[ "$1"  =~ .*SNAPSHOT.* ]]; then

    echo "Working with SNAPSHOT"
    export VERSION=$(curl -s https://repo.govkg.de/repository/autent-snapshots/de/governikus/eumw/eidas-middleware/$1/maven-metadata.xml | grep "<value>.*</value>" | sed -e "s#\(.*\)\(<value>\)\(.*\)\(</value>\)\(.*\)#\3#g" | head -n 1)
    echo "Downloading JAR in Version $VERSION"
    wget -P resources --content-disposition "https://repo.govkg.de/repository/autent-snapshots/de/governikus/eumw/eidas-middleware/$1/eidas-middleware-$VERSION.jar"
    ls -la resources
else
    echo "Working with Release"
    wget -P resources --content-disposition "https://repo.govkg.de/repository/autent-releases/de/governikus/eumw/eidas-middleware/$1/eidas-middleware-$1.jar"
    export VERSION=$1
fi

# execute packer
echo "Executing packer"
if ! packer build -color=false -var "source-path=$2" eidasmw_appliance.json; then
    echo "PACKER FAILED"
    exit 1
fi

# cleanup
echo "Cleanup"
rm -r resources
rm -r packer_cache
