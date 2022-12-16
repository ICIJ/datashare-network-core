# datashare network core library [![CircleCI](https://circleci.com/gh/ICIJ/datashare-network-core/tree/main.svg?style=svg&circle-token=4114eed623f62c2c3896785aceee50af0457e4ce)](https://circleci.com/gh/ICIJ/datashare-network-core/tree/main)

This is the core library for the protocol described in the EPFL paper:

[DATASHARENETWORK A Decentralized Privacy-Preserving Search Engine for Investigative Journalists](https://arxiv.org/pdf/2005.14645.pdf)

This is a work in progress.

To develop, [install Poetry](https://python-poetry.org/docs/#installation) then just run:

```
make install
make test
```

To run tests with watcher:

```
make test-watch
```

## Release

Mark the version (choose the correct one following [semver](https://semver.org/)):

```
make patch
make minor
make major
```

To set a specific version use this command:

```
make set_version CURRENT_VERSION=X.Y.Z
```

To build the Python package:

```
make clean dist
```

To publish the package on pypi:

```
make distribute
```
