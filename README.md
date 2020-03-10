Intel(R) Software Guard Extensions for Linux\* OS
================================================

# linux-sgx

Introduction
------------
Intel(R) Software Guard Extensions (Intel(R) SGX) is an Intel technology for application developers seeking to protect select code and data from disclosure or modification.

The Linux\* Intel(R) SGX software stack is comprised of the Intel(R) SGX driver, the Intel(R) SGX SDK, and the Intel(R) SGX Platform Software (PSW). The Intel(R) SGX SDK and Intel(R) SGX PSW are hosted in the [linux-sgx](https://github.com/01org/linux-sgx) project.

The [linux-sgx-driver](https://github.com/01org/linux-sgx-driver) project hosts the out-of-tree driver for the Linux\* Intel(R) SGX software stack, which will be used until the driver upstreaming process is complete. 

License
-------
See [License.txt](License.txt) for details.

Contributing
-------
See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

Documentation
-------------
- [Intel(R) SGX for Linux\* OS](https://01.org/intel-softwareguard-extensions) project home page on [01.org](https://01.org)
- [Intel(R) SGX Programming Reference](https://software.intel.com/sites/default/files/managed/48/88/329298-002.pdf)

Build and Install the Intel(R) SGX Driver
-----------------------------------------
Follow the instructions in the [linux-sgx-driver](https://github.com/01org/linux-sgx-driver) project to build and install the Intel(R) SGX driver.

Build the Intel(R) SGX PSW Package
-------------------------------------------------------
### Prerequisites:
- Ensure that you have one of the following required operating systems:  
  * Ubuntu\* 16.04.1 LTS Desktop 64bits
  * Ubuntu\* 16.04.1 LTS Server 64bits

- Use the following command to install additional required tools to build the Intel(R) SGX PSW:  
  * On Ubuntu 16.04:
  ```
    $ sudo apt-get install libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev
  ```
- Use the script ``download_prebuilt.sh`` inside source code package to download prebuilt binaries to prebuilt folder  
  You may need set an https proxy for the `wget` tool used by the script (such as ``export https_proxy=http://test-proxy:test-port``)  
```
  $ ./download_prebuilt.sh
```

### Build the Intel(R) SGX PSW
The following steps describe how to build the Intel(R) SGX PSW. You can build the project according to your requirements.  
- To build both Intel(R) SGX PSW with default configuration, enter the following command:  
```
  $ make  
```  
  You can find the tools and libraries generated in the `build/linux` directory.  
  **Note**: You can also go to the `sdk` folder and use the `make` command to build the Intel(R) SGX SDK component only. However, building the PSW component is dependent on the result of building the Intel(R) SGX SDK.  

- To build Intel(R) SGX PSW with debug information, enter the following command:  
```
  $ make DEBUG=1
```
- To clean the files generated by previous `make` command, enter the following command:  
```
  $ make clean
```

### Build the Intel(R) SGX PSW Installer
To build the Intel(R) SGX PSW installer, enter the following command:
```
$ make psw_install_pkg
```
You can find the generated Intel(R) SGX PSW installer ``sgx_linux_x64_psw_${version}.bin`` located under `linux/installer/bin/`, where `${version}` refers to the version number.

**Note**: The above command builds the Intel(R) SGX PSW with default configuration firstly and then generates the target PSW Installer. To build the Intel(R) SGX PSW Installer with debug information kept in the tools and libraries, enter the following command:
```
$ make psw_install_pkg DEBUG=1
```


Install the Intel(R) SGX PSW
----------------------------
### Prerequisites
- Ensure that you have one of the following operating systems:  
  * Ubuntu\* 16.04.1 LTS Desktop 64bits
  * Ubuntu\* 16.04.1 LTS Server 64bits
- Ensure that you have a system with the following required hardware:  
  * 6th Generation Intel(R) Core(TM) Processor or newer
- Configure the system with the **Intel SGX hardware enabled** option and install Intel(R) SGX driver in advance.  
  See the earlier topic, *Build and Install the Intel(R) SGX Driver*, for information on how to install the Intel(R) SGX driver.
- Install the library using the following command:  
  * On Ubuntu 16.04:
  ```
    $ sudo apt-get install libssl-dev libcurl4-openssl-dev libprotobuf-dev
  ```
### Install the Intel(R) SGX PSW
To install the Intel(R) SGX PSW, invoke the installer with root privilege:  
```
$ cd linux/installer/bin
$ sudo ./sgx_linux_x64_psw_${version}.bin
```

### Start or Stop aesmd Service
The Intel(R) SGX PSW installer installs an aesmd service in your machine, which is running in a special linux account `aesmd`.  
To stop the service: `$ sudo service aesmd stop`  
To start the service: `$ sudo service aesmd start`  
To restart the service: `$ sudo service aesmd restart`

### Configure the Proxy for aesmd Service
The aesmd service uses the HTTP protocol to initialize some services.  
If a proxy is required for the HTTP protocol, you may need to manually set up the proxy for the aesmd service.  
You should manually edit the file `/etc/aesmd.conf` (refer to the comments in the file) to set the proxy for the aesmd service.  
After you configure the proxy, you need to restart the service to enable the proxy.
