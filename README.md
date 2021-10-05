[![][License img]][License]
[![][MainRepo img]][MainRepo]
[![][AltRepo img]][AltRepo]

<a href="http://lpsc.in2p3.fr/" target="_blank">
	<img src="http://ami.in2p3.fr/docs/images/logo_lpsc.png" alt="LPSC" height="72" />
</a>
&nbsp;&nbsp;&nbsp;&nbsp;
<a href="http://www.in2p3.fr/" target="_blank">
	<img src="http://ami.in2p3.fr/docs/images/logo_in2p3.png" alt="IN2P3" height="72" />
</a>
&nbsp;&nbsp;&nbsp;&nbsp;
<a href="http://www.univ-grenoble-alpes.fr/" target="_blank">
	<img src="http://ami.in2p3.fr/docs/images/logo_uga.png" alt="UGA" height="70" />
</a>
&nbsp;&nbsp;&nbsp;&nbsp;
<a href="http://home.cern/" target="_blank">
	<img src="http://www.cern.ch/ami/images/logo_atlas.png" alt="CERN" height="80" />
</a>
&nbsp;&nbsp;&nbsp;&nbsp;
<a href="http://atlas.cern/" target="_blank">
	<img src="http://ami.in2p3.fr/docs/images/logo_cern.png" alt="CERN" height="72" />
</a>

What is mosquitto-ip-jwt-auth?
==============================

IP and [JWT](https://jwt.io/) authentication plugin for [Eclipse Mosquitto 2](https://mosquitto.org/).

[![JWT](http://jwt.io/img/badge-compatible.svg)](https://jwt.io/)

Installing mosquitto-ip-jwt-auth
================================

* Requirements:

Make sure that [Eclipse Mosquitto 2](https://www.mosquitto.org/), [gcc](https://www.gnu.org/software/gcc/) / [clang](https://clang.llvm.org/), [cmake](https://cmake.org/) and [make](https://www.gnu.org/software/make/) are installed:
```bash
mosquitto --version
gcc --version
cmake --version
make --version
```

* Compiling:

```bash
make deps all
```

* Configuring:

| Parameter        | Optional | Desccription                                              | Desccription                         | Default value |
|------------------|----------|-----------------------------------------------------------|--------------------------------------|---------------|
| allowed_ips      | yes      | Allowed IPs                                               | space-separated list of IPs (64 max) | *empty*       |
| jwt_signing_alg  | yes      | JWT signing algorithm                                     | See below †                          | HS512         |
| jwt_secret_key   | yes      | JWT secret key                                            | Free string                          | *empty*       |
| jwt_issuer       | yes      | If not empty, validate issuer (iss data payload)          | Free string                          | *empty*       |
| jwt_validate_sub | yes      | If not empty, check subject (sub data payload) = username | 0 or 1                               | 1             |
| jwt_validate_exp | yes      | Check expiration time (exp data payload)                  | 0 or 1                               | 0             |
| jwt_validate_nbf | yes      | Check not febore time (nbf data payload)                  | 0 or 1                               | 0             |
| jwt_validate_iat | yes      | Check issued at time (ita data payload)                   | 0 or 1                               | 0             |

> † Supported signing algorithms: HS256, HS384, HS512, PS256, PS384, PS512, RS256, RS384, RS512, ES256, ES256K, ES384, ES512, EdDSA.

Example of `mosquitto.conf` file:
```
plugin <install_path>/ip-jwt-auth.so

plugin_opt_allowed_ips <my_ip1> <my_ip2> <...>

plugin_opt_jwt_signing_alg HS512

plugin_opt_jwt_secret_key <my_secret_key>

plugin_opt_jwt_issuer <my_issuer>

plugin_opt_jwt_validate_exp 1
```

Developer
=========

* [Jérôme ODIER](https://www.odier.xyz/) ([CNRS/LPSC](http://lpsc.in2p3.fr/))

[License]:http://www.cecill.info/licences/Licence_CeCILL-C_V1-en.txt
[License img]:https://img.shields.io/badge/license-CeCILL--C-blue.svg

[MainRepo]:https://gitlab.in2p3.fr/ami-team/mosquitto-ip-jwt-auth/
[MainRepo img]:https://img.shields.io/badge/Main%20Repo-gitlab.in2p3.fr-success

[AltRepo]:https://github.com/odier-io/mosquitto-ip-jwt-auth/
[AltRepo img]:https://img.shields.io/badge/Alt%20Repo-github.com-success
