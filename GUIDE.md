# OT Registrar Guide

## Setup

All setup commands assume you are starting in the project's root directory.

1. Bootstrap

    Install the [java](https://openjdk.java.net/), [maven](https://maven.apache.org/), and [ace-java](https://bitbucket.org/marco-tiloca-sics/ace-java) packages:

    ```bash
    ./script/bootstrap.sh
    ```

2. Build

    Run unit tests and build the OT Registrar JAR package:

    ```bash
    mvn package
    ```

    To skip the tests:

    ```bash
    mvn -DskipTests package
    ```

    This creates a JAR file at `target/ot-registrar-0.1-SNAPSHOT-jar-with-dependencies.jar`.

## Run services

The OT Registrar JAR file includes the [Registrar](https://tools.ietf.org/id/draft-ietf-anima-bootstrapping-keyinfra-16.html#rfc.section.1.2), [MASA](https://tools.ietf.org/id/draft-ietf-anima-bootstrapping-keyinfra-16.html#rfc.section.1.2) server, and a simulated [Pledge](https://tools.ietf.org/id/draft-ietf-anima-bootstrapping-keyinfra-16.html#rfc.section.1.2).

### Credentials

To run the registrar or MASA server, we need a structured keystore file (in PKCS#12 format) containing the credentials.

See [credentials/README.md](credentials/README.md) for details on how to generate credentials. For this guide, we'll use the
`threadgroup-5f9d307c.p12` credentials provided with OT Registrar.

### Run the registrar

Start the registrar at port 5684, using the `threadgroup-5f9d307c.p12` credentials:

```bash
java -cp target/ot-registrar-0.1-SNAPSHOT-jar-with-dependencies.jar com.google.openthread.registrar.RegistrarMain -d Thread -f credentials/threadgroup-5f9d307c.p12 -p 5684
```

Use the `-h` option to learn what arguments are available:

```bash
java -cp target/ot-registrar-0.1-SNAPSHOT-jar-with-dependencies.jar com.google.openthread.registrar.RegistrarMain -h
# usage: registrar -d <domain-name> -f <keystore-file> -p <port>
#  -d,--domainname <domain-name>   the domain name
#  -f,--file <keystore-file>       the keystore file in PKCS#12 format
#  -h,--help                       print this message
#  -p,--port <port>                the port to listen on
#  -v,--verbose                    verbose mode with many logs
```

### Run the MASA server

Start the MASA server at port 5685, using the `threadgroup-5f9d307c.p12` credentials:

```bash
java -cp target/ot-registrar-0.1-SNAPSHOT-jar-with-dependencies.jar com.google.openthread.masa.MASAMain -f credentials/threadgroup-5f9d307c.p12 -p 5685
```

Use the `-h` option to learn what arguments are available:

```bash
java -cp target/ot-registrar-0.1-SNAPSHOT-jar-with-dependencies.jar com.google.openthread.masa.MASAMain -h
# usage: masa -a <alias> -f <keystore-file> -p <port>
#  -a,--alias <alias>          the masa keystore alias
#  -f,--file <keystore-file>   the keystore file in PKCS#12 format
#  -h,--help                   print this message
#  -p,--port <port>            the port to listen on
#  -v,--verbose                verbose mode with many logs
```

### Run the pledge

Use a simulated pledge to test the Registrar.

Start the pledge:

```bash
java -cp target/ot-registrar-0.1-SNAPSHOT-jar-with-dependencies.jar com.google.openthread.pledge.PledgeMain -f credentials/threadgroup-5f9d307c.p12 -r "[::1]:5684"
# ...
# >
```

The pledge enters interactive mode and waits for user commands. Press **Enter** or type `help` to get a list of all available commands:

```text
> help
token    -  request commissioning token
rv       -  request voucher
attrs    -  request CSR attributes
enroll   -  simple enrollment
reenroll -  simple reenrollment
reset    -  reset to initial state
exit     -  exit pledge CLI
help     -  print this help message

done
>
```

Use the `exit` command to exit or **Ctrl+c** to force exit.

### Run the Thread Registrar Interface (TRI)

A TRI is needed to connect Thread devices with a registrar. Please see the [TRI project](https://bitbucket.org/threadgroup/tce-registrar-java) for instructions.

> Note: Only Thread Group members can access the TRI project.

There is script [script/run-servers.sh](script/run-servers.sh) that starts all those servers in the background with the default arguments.

## The Docker service

You can use `script/run-servers.sh` to run all services in a local host. To avoid having to frequently start and stop all three servers, OT Registrar provides a Docker image to start all services with a single command.

_**Note:** Only supported on Linux._

1. Complete the [setup](#setup) if you haven't already.

2. Build the Docker image:

    ```bash
    ./script/build-docker-image.sh
    ```

3. Start all services:

    ```bash
    ./script/start-services.sh
    ```
