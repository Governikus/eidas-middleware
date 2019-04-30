# Governikus eIDAS Middleware

This repository contains the source code of the German eIDAS middleware.

## Releases
With every release, the source code of our internal repository will be exported into this repository. 
The signed release artifacts will be released on github as well.

## Build
### Building the java sources
We are using maven to build and test the software.

To build the software, execute the following command:
```
maven clean install
```
You can find the compiled JARs in the `target/` directory of each module.

### Building the documentation
The source for the documentation can be found in the `doc` folder.

To build a pdf file, _sphinx_ is needed. Please see the [sphinx documentation](http://www.sphinx-doc.org/en/master/usage/installation.html)
on how to install sphinx on your system. 

To create the pdf file, issue the following commands:

```
cd doc && make clean latexpdf
```

The created pdf document can be found at `_build/latex/eIDASMiddleware.pdf`.

## Documentation
The user documentation for each release is available in the release artifacts.

## Contributing
Please see [CONTRIBUTING.md](CONTRIBUTING.md) for more information on how to submit pull requests.

## License
Copyright &copy; 2019 Governikus KG
 
This work is licensed under the EUPL 1.2. See LICENSE.txt for additional information.

The overview of the used third party dependecies and their licenses is available in the release documents.
 
