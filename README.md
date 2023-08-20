# Electro Wizard

- [Electro Wizard](#electro-wizard)
  - [About](#about)
  - [Requirements](#requirements)
  - [Installation](#installation)
    - [1. Clone the repository](#1-clone-the-repository)
    - [2. Install Python Virtualenv](#2-install-python-virtualenv)
    - [3. Prepare the virtual environment](#3-prepare-the-virtual-environment)
    - [4. Activate the virtualenv](#4-activate-the-virtualenv)
    - [5. Install Python dependencies](#5-install-python-dependencies)
  - [Flags](#flags)
  - [SSL Cert](#ssl-cert)
    - [1. Install OpenSSL](#1-install-openssl)
    - [2. Generate a private key](#2-generate-a-private-key)
    - [3. Generate a certificate signing request (CSR)](#3-generate-a-certificate-signing-request-csr)
    - [4. Generate the self-signed certificate](#4-generate-the-self-signed-certificate)
  - [Reverse Proxy on aspj.mikoshi.foo](#reverse-proxy-on-aspjmikoshifoo)
  - [Server Hosting](#server-hosting)

## About

Our web application is to spread awareness about climate change and global warming, and also encourage people to fight climate change by saving their electricity consumption. Users will be able to upload their electricity bills, which will earn them points that they can use to redeem items from shops. Users will also be able to complete missions related to saving the environment to earn points. The website allows visitors to donate to organizations that fight climate change.  

## Requirements

- Python 3.8 and above
- Linux or WSL for flags support

## Installation

### 1. Clone the repository

```sh
git clone https://github.com/MaxwellX5/ApplicationSecurityProject.git
```

### 2. Install Python Virtualenv

```sh
pip install virtualenv
```

### 3. Prepare the virtual environment

This will create a new directory `venv` that contains the virtual environment for the application.  

```sh
cd ApplicationSecurityProject
python -m venv venv
```

### 4. Activate the virtualenv

- Linux:

  ```sh
  source venv/bin/activate
  ```

- Windows:  

  ```dos
  .\venv\Scripts\activate
  ```

### 5. Install Python dependencies

```sh
python __init__.py
```

> See the `Flags` section for more options.  

## Flags

> Note: Flags are enabled for Linux systems only, default values are selected when on Windows

Default host and port is `127.0.0.1:5000`.  
Default protocol is `http`.  

To enable support for domain names, add the `--domain` flag when running the `__init__.py` file.  
Only use this when running from a port forwarded host.  
Example: `python __init__.py --domain aspj.mikoshi.foo`

To enable https due to annoyance of having to accept the self-signed certificate, add the `--https` flag when running the `__init__.py` file.  
This is not neccessary when using a reverse proxy with SSL connections already enabled.  
PEM pass phrase is: `Password!23`  
Example: `python __init__.py --https`

To change the host, add the `--host` flag when running the `__init__.py` file.  
Example: `python __init__.py --host 192.168.0.70`

To change the port, add the `--port` flag when running the `__init__.py` file.  
Example: `python __init__.py --port 3069`

To fetch public IP for access from outside network, add the `--ip` flag when running the `__init__.py` file.  
This is only used when port forwarding is used but domain names are not.  
Example: `python __init__.py --ip`

| Flag       | Description            | Example                                        |
| ---------- | ---------------------- | ---------------------------------------------- |
| `--domain` | Enables domain support | `python __init__.py --domain aspj.mikoshi.foo` |
| `--https`  | Enables HTTPS          | `python __init__.py --https`                   |
| `--host`   | Changes the host       | `python __init__.py --host`                    |
| `--port`   | Changes the port       | `python __init__.py --port 42069`              |
| `--ip`     | Fetches public IP      | `python __init__.py --ip`                      |

> ### Troubleshooting
>
> ```sh
> usage: __main__.py [-h] [--http] [--host HOST] [--port PORT]
> __main__.py: error: unrecognized arguments: run
> ```
>
> This error is caused by PyCharm running the `python -m flask run` command, which is not supported by the flags.
> Solution: spam ping me or just run the `__init__.py` file directly.
> `python __init__.py`

## SSL Cert

### 1. Install OpenSSL

- Arch Linux

```sh
sudo pacman -S openssl
```

- Ubuntu or Debian

```sh
sudo apt install openssl
```

### 2. Generate a private key

This command generates a private key using the RSA algorithm and AES-256 encryption. It will prompt you to enter a password for the private key.
PEM pass phrase: `Password!23`

```sh
openssl genpkey -algorithm RSA -out private.key -aes256
```

### 3. Generate a certificate signing request (CSR)

This command generates a CSR using the private key generated in the previous step. It will prompt you to provide information such as the common name (CN) for the certificate.

```sh
openssl req -new -key private.key -out csr.csr
```

Enter as follows:

```plaintext
Country Name (2 letter code) [AU]:SG
State or Province Name (full name) [Some-State]:Singapore
Locality Name (eg, city) []:Singapore
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Vomitblood
Organizational Unit Name (eg, section) []:Vomitblood
Common Name (e.g. server FQDN or YOUR name) []:Vomitblood
Email Address []:tohyouxuan@gmail.com

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:Vomitblood
```

### 4. Generate the self-signed certificate

This command generates a self-signed certificate using the CSR and private key generated earlier. The certificate will be valid for 69420 days (this can be adjusted).

```sh
openssl x509 -req -days 69420 -in csr.csr -signkey private.key -out certificate.crt
```

> Verify the generated files:
>
> - `private.key`: The private key file.
> - `csr.csr`: The certificate signing request file.
> - `certificate.crt`: The self-signed certificate file.

## Reverse Proxy on aspj.mikoshi.foo

Nginx is used as a reverse proxy.  
All http requests are redirected to port 3069 via Nginx.  
The TLS certificate used is issued by Google Trust Services, using an EAB key provided.  
Certbot ACME client with Nginx plugin is used to request a certificate, with auto renewal enabled.  
`sudo certbot --nginx -d aspj.mikoshi.foo`

## Server Hosting

The server domain name is located at `aspj.mikoshi.foo`.  
User configured to run this is `tnmt`.  
Application code is located at `/home/tnmt/Build/AppSecurityFr/`.  
Python Virtualenv is located at `/home/tnmt/BUild/AppSecurityFr/venv/`.  