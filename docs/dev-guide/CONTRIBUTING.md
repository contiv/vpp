## Contiv-VPP Contribution Guidelines

Contributions to Contiv-VPP are welcome. We use the standard pull request
model. You can either pick an open issue and assign it to yourself or open
a new issue and discuss your feature.

In any case, before submitting your pull request please check the
[Coding style](https://github.com/ligato/cn-infra/blob/master/docs/guidelines/CODINGSTYLE.md)
and cover the newly added code with tests and
documentation (Contiv-VPP adopted the coding style used in the
[Ligato](https://github.com/ligato) project). Upon submission, each patch is run through
the `go fmt` and `golint` tools.

The tool used for managing third-party dependencies is [Dep](https://github.com/golang/dep).
After adding or updating a dependency in `Gopkg.toml` run `make install-dep` to
download the specified dependencies into the vendor folder. Please make sure
that each dependency in the `Gopkg.toml` has a specific `version` defined
(a specific commit ID or a git tag).
