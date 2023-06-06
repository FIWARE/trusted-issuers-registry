# Trusted Issuers Registry

The Trusted Issuers Registry provides both an [EBSI Trusted Issuers Registry](https://api-pilot.ebsi.eu/docs/apis/trusted-issuers-registry/v4#/) implementation and an iShare implementation. The service provides data from an NGSI-LD compliant backend and configuration files.

[![FIWARE Security](https://nexus.lab.fiware.org/repository/raw/public/badges/chapters/security.svg)](https://www.fiware.org/developers/catalogue/)
[![License badge](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Coverage Status](https://coveralls.io/repos/github/fiware/trusted-issuers-registry/badge.svg?branch=main)](https://coveralls.io/github/fiware/trusted-issuers-registry?branch=main)
[![Test](https://github.com/fiware/trusted-issuers-registry/actions/workflows/test.yml/badge.svg)](https://github.com/FIWARE/trusted-issuers-registry/actions/workflows/test.yml)
[![Release](https://github.com/fiware/trusted-issuers-registry/actions/workflows/release.yml/badge.svg)](https://github.com/FIWARE/trusted-issuers-registry/actions/workflows/release.yml)

## Installation
### Container

The Trusted Issuers Registry is provided as a container at [quay.io](https://quay.io/repository/fiware/trusted-issuers-registry).
To provide the service, a NGSI-LG service has to be provided. In a local setup, you can for example use:
```shell
docker run --name orionld -p 1206:1206 quay.io/fiware/orion-ld:1.1.1
```
and the start the service:
```shell
docker run --network host quay.io/fiware/trusted-issuers-registry:0.0.1
```
After that, its accessible at ```localhost:8080```.
### Helm Chart

More convinient deployment is available via the [Helm Chart](https://github.com/FIWARE/helm-charts/tree/main/charts/trusted-issuers-registry)

### Configuration

Configurations can be provided with the standard mechanisms of the [Micronaut-Framework](https://micronaut.io/), e.g. [environment variables or appliction.yaml file](https://docs.micronaut.io/3.1.3/guide/index.html#configurationProperties).
The following table concentrates on the most important configuration parameters:

| Property                           | Env-Var                            | Description                                                  | Default                   |
|------------------------------------|------------------------------------|--------------------------------------------------------------|---------------------------|
| `micronaut.server.port`            | `MICRONAUT_SERVER_PORT`            | Server port to be used.                                      | 8080                      |
| `micronaut.metrics.enabled`        | `MICRONAUT_METRICS_ENABLED`        | Enable the metrics gathering                                 | true                      |
| `micronaut.http.services.ngsi.url` | `MICRONAUT_HTTP_SERVICES_NGSI_URL` | Url of the backing NGSI-LD broker                            | ```http://ngsi-ld:1026``` |
| `general.contextUrl`               | `GENERAL_CONTEXT_URL`              | URL of the Context file to be used when accessing the broker | ``````                    |


## License

Trusted Issuers Registry is licensed under the Apache License, Version 2.0. See LICENSE for the full license text.

© 2023 FIWARE Foundation e.V.