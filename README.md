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

mosquitto-ami-auth
==================

IP and JWT authentication plugin for [Eclipse Mosquitto 2](https://mosquitto.org/).

Installing mosquitto-ami-auth
=============================

* Requierments:

Make sure that [Eclipse Mosquitto 2](https://mosquitto.org/), [gcc](https://www.gnu.org/software/gcc/) or [clang](https://clang.llvm.org/), [cmake](https://cmake.org/) and [make](https://www.gnu.org/software/make/) are installed:
```bash
mosquitto --version
gcc --version
cmake --version
make --version
```

* Compiling and installing:

```bash
make deps all
```

In `/etc/mosquitto/mosquitto.conf`:
```
plugin <install_path>/ami-auth.so

plugin_opt_allowed_ips <ip1> <ip2> <...>

plugin_opt_jwt_secret_key <my_secret_key>

plugin_opt_jwt_issuer <my_issuer>
```

[License]:http://www.cecill.info/licences/Licence_CeCILL-C_V1-en.txt
[License img]:https://img.shields.io/badge/license-CeCILL--C-blue.svg
