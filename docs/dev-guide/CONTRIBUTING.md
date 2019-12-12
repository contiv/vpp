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

Dependencies are managed using [go modules](https://blog.golang.org/using-go-modules).
To download dependencies, run `make dep-install`.
