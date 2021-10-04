[![][License img]][License]

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

What is mosquitto-ami-auth?
===========================

IP and [JWT](https://jwt.io/) authentication plugin for [Eclipse Mosquitto 2](https://mosquitto.org/).

[![JWT](http://jwt.io/img/badge-compatible.svg)](https://jwt.io/)

Installing mosquitto-ami-auth
=============================

* Requierments:

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

`/etc/mosquitto/mosquitto.conf`:
```
plugin <install_path>/ami-auth.so

plugin_opt_allowed_ips <my_ip1> <my_ip2> <...>

plugin_opt_jwt_secret_key <my_secret_key>

plugin_opt_jwt_issuer <my_issuer>

plugin_opt_jwt_validate_exp <0|1>

plugin_opt_jwt_validate_iat <0|1>
```

JWT details
===========

Supported signing algorithms: HS256, HS384, HS512, PS256, PS384, PS512, RS256, RS384, RS512, ES256, ES256K, ES384, ES512, EdDSA.

Madatory payload data entries :
```json
{
	"iss": "<issuer>",
	"sub": "<subject>"
}
```

Developer
=========

* [Jérôme ODIER](https://www.odier.xyz/) ([CNRS/LPSC](http://lpsc.in2p3.fr/))

[License]:http://www.cecill.info/licences/Licence_CeCILL-C_V1-en.txt
[License img]:https://img.shields.io/badge/license-CeCILL--C-blue.svg
