# Network traffic analysis

Le Deep Packet Inspection (DPI), en français Inspection des Paquets en Profondeur, est l'activité d'analyser le contenu (au-delà de l'en-tête) d'un paquet réseau (paquet IP le plus souvent) de façon à en tirer des statistiques, à filtrer ceux-ci ou à détecter des intrusions, du spam ou tout autre contenu prédéfini.

Le but de ce projet c'est d'afficher les informations contenue dans un fichier .pcap selon le protocole choisi.

- `in` : un fichier .pcap

- `out` : les valeurs des différents champs du protocole

## Install guide

### Dependencies

You need `libpcap` to be able to compile and run the program

1. in `Macos` :

```shell
$ brew install libpcap
```

For `pkg-config` to find libpcap you may need to set:

```shell
$ export PKG_CONFIG_PATH="/usr/local/opt/libpcap/lib/pkgconfig:$PKG_CONFIG_PATH"
```

2. in `Linux` :

```shell
$ sudo apt-get update -y
$ sudo apt-get install -y libpcap-dev
```

### Compilation

You can compile the project using the `make` command:

```shell
$ cd dpi-project
$ make
```

It will create a file name `dpi`. Then, you can launch the executable with:

```shell
$ ./dpi <pcap file>
```

You can test the project using the `make` command:

```shell
$ make test
```

You can clean the project using the `make` command:

```shell
$ make clean
```
