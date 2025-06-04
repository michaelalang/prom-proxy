# Perses setup

with v2.0.0 and using `x-id-token` you need to create the datasources accordingly.

in the file `create` adjust the line
```
export token=$(oidc -u $(basename -s .json ${src} | cut -f2 -d'-'))
```

to fetch an OIDC JWT token into the datasources that are created.
Once done call `./create` to deploy Project, datasource and dashboards accordingly.
