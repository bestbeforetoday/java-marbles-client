
# Integration of Hyperledger Fabric Java Gateway with HSM
This document contains the instructions to set up an HSM and configure the system so that the Hyperledger Fabric Java Gateway can make use of the HSMWallet.  
  
This code has been tested successfully using the AWS CloudHM.
However, when testing with the SoftHSM, there is an issue that prevents a successful execution:   
```  
java.lang.ClassCastException: class sun.security.pkcs11.P11Key$P11PrivateKey cannot be cast to class java.security.interfaces.ECPrivateKey (sun.security.pkcs11.P11Key$P11PrivateKey is in module jdk.crypto.cryptoki of loader 'platform'; java.security.interfaces.ECPrivateKey is in module java.base of loader 'bootstrap')
```   

## Setup

This set of instructions apply to an Ubuntu 16.04 VM:

#### Installing SoftHSM:  
`sudo apt-get install -y softhsm`  
`mkdir -p $HOME/lib/softhsm/tokens`  
`cd $HOME/lib/softhsm/`  
`echo "directories.tokendir = $PWD/tokens" > softhsm2.conf`  

#### Configuring local SoftHSM environment 
`export SOFTHSM2_CONF=$HOME/lib/softhsm/softhsm2.conf`  
`echo "export SOFTHSM2_CONF=$HOME/lib/softhsm/softhsm2.conf" > $HOME/.bashrc`  
`softhsm2-util --init-token --slot 0 --label "hlf_client" --so-pin 1234 --pin 1234`  

#### Checking the HSM is properly initialized

Running this command:
`softhsm2-util --show-slots` should result in:   
**IMPORTANT:** Make note of the Slot number. In this example: 1227366935
```
Available slots:
Slot 1227366935
    Slot info:
        Description:      SoftHSM slot ID 0x49282217                                      
        Manufacturer ID:  SoftHSM project                 
        Hardware version: 2.2
        Firmware version: 2.2
        Token present:    yes
    Token info:
        Manufacturer ID:  SoftHSM project                 
        Model:            SoftHSM v2      
        Hardware version: 2.2
        Firmware version: 2.2
        Serial number:    07b731bf49282217
        Initialized:      yes
        User PIN init.:   yes
        Label:            HLF_Wallet                      
Slot 1
    Slot info:
        Description:      SoftHSM slot ID 0x1 
```  

#### Setting up Java Security to integrate with the SoftHSM
From the folder: `$JAVA_HOME/conf/Security`  

1. Edit the java.security SunPKCS11 provider  
   `vi java.security`  
   locate the line `security.provider.12=SunPKCS11` and modify it so it looks as follow:
    ```
    security.provider.12=SunPKCS11 ${java.home}/conf/security/pkcs11.cfg
    ```
1. Create the pkcs11.cfg config file  
   File must be located under `${java.home}/conf/security/pkcs11.cfg`
   Content must be:
   ```
    library=/usr/lib/softhsm/libsofthsm2.so
    name=softhsm2
    slot=1227366935
    ```
    **IMPORTANT** Note that the slot number must match the one you noted previously.

#### Importing the admin cert in the Java SunPKCS11 KeyStore  
From the wallet directory of the `admin` identity, run the following commands:  

1. Extract the certificate from the admin json file.  
`jq -r .enrollment.identity.certificate admin > admin-cert.pem`  

2. Convert the certificate and private key to the PKCS12 format.  
`openssl pkcs12 -export -in admin-cert.pem -inkey 1ae0690a6994514b0200a5d3aa524f90fe17e37f0200a6a5e38f96664f630f89-priv  -out admin.p12`  

3.  Import the PKCS12 format to the SoftHSM KeyStore.
`$JAVA_HOME/bin/keytool -importkeystore -deststorepass 1234 -destkeystore NONE -deststoretype PKCS11 -srckeystore admin.12 -srcstoretype PKCS12`

4. Rename the KeyStore alias from `1` to `admin`  
   `$JAVA_HOME/bin/keytool -changealias -keystore NONE -storetype PKCS11 -alias "1" -destalias "admin"`

### Running the sample  

Assuming the local Fabric network is up, the channel is defined and the smart contract is deployed (Marbles02) then run the following:

Note that the application refers to the folders under the local home directory `.fabric-vscode` to find the gateway and wallets.

1. Compile the code  
   `mvn compile`  

2. Run the application  
   `mvn exec:java -Dexec.mainClass="com.mycompany.app.App"`  

References:
* [Building Java Applications](https://guides.gradle.org/building-java-applications/)
* [Maven in 5 Minutes](https://maven.apache.org/guides/getting-started/maven-in-five-minutes.html)
* [3 ways to run Java main from Maven](http://www.vineetmanohar.com/2009/11/3-ways-to-run-java-main-from-maven/)
