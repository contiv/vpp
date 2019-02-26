# Contiv-VPP Release Procedure

Given a version number `vMAJOR.MINOR.PATCH` pick a version:
- PATCH releases: `vX.Y.<version>` : bug fixes
- MINOR releases: `vX.<version>.0` : control plane changes & new features, backward compatible changes
- MAJOR releases: `v<version>.0.0` : VPP release change, backward incompatible changes  

1. Update [CHANGELOG](../../CHANGELOG.md) with release name, date and list of changes.
2. Update [Chart.yaml](../../k8s/contiv-vpp/Chart.yaml) with the new version (with `v` prefix).
3. Draft a new release:
   
   - Go to: https://github.com/contiv/vpp/releases
   - Click on "Draft a new release"
   - Enter:
   
     **Tag version** (with `v` prefix): `vX.Y.Z`
     
     **Release title**: Version `X.Y.Z`
     
     **Release Description** (optionally add `#anchor` pointing to the release at the end of the link): 
     ```
     See [CHANGELOG](https://github.com/contiv/vpp/blob/master/CHANGELOG.md).
     ```

4. Wait for Docker images build.
5. Re-tag Docker images to release version (`vX.Y.Z`) without prefixes.
