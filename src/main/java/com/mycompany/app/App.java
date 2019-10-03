package com.mycompany.app;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

import org.apache.log4j.Logger;
import org.hyperledger.fabric.gateway.Contract;
import org.hyperledger.fabric.gateway.Gateway;
import org.hyperledger.fabric.gateway.Network;
import org.hyperledger.fabric.gateway.Wallet;

// Unfortunately, there is no asLocalhost setting in the fabric-gateway-java lib... the fabric-newtwork npm module for Node.js has this setting.
// The fabric-gateway-java should be updated to include this setting...
// In the meantime, as a workaround, you need to update /etc/hosts accordingly (for more details see https://github.com/hyperledger/fabric-gateway-java#building-and-testing)
// As reference, see below:
// 127.0.0.1 ca0.example.com
// 127.0.0.1 ca1.example.com
// 127.0.0.1 orderer.example.com
// 127.0.0.1 peer0.org1.example.com
// 127.0.0.1 peer0.org2.example.com
// 127.0.0.1 peer1.org2.example.com
// 127.0.0.1 peer1.org1.example.com 

// Could not get the application to build/compile using Gradle... 
// The root cause of the problem seems to be the following (which does not look right) -> https://github.com/hyperledger/fabric-gateway-java/blob/master/pom.xml#L77
// That line in the POM is referencing version 1.4.5 of the Fabric JAVA SDK... however, the latest version of the JAva SDK is 1.4.4.
// As reference, see https://mvnrepository.com/artifact/org.hyperledger.fabric-sdk-java/fabric-sdk-java

// Because of the above issue, I had to switch to maven (instead of gradle).
// For some reason, maven is not thrown off by the dependency on Fabric Java SDK 1.4.5.

// Running this code you can successfully query and update the ledger (marbles chaincode).
// However, before the process finishes, an IllegalThreadStateException is thrown...
// It looks like the SDK has 10 lingering threads that for some reason it is not closing.
// Please note that the Gateway object implements the AutoClose interface.
// Therefore, the close method is called by the try-catch block at the end of that block's execution... 
// Not sure yet why these 10 threads are still running...

// A few points to notice:
// channel name hardcoded to 'mychannel'
// chaincode name hardcoded to 'marbles'
// Using identity for 'user1' (previously created using the enrollment function against a running Fabric CA); path to the wallet is hardcoded below!
// Using the connection profile for the first-network (Org1), path is hardcoded below!

// mvn compile - compiles the code 
// mvn exec:java -Dexec.mainClass="com.mycompany.app.App" - runs the app

public class App {
    // logger
    final static Logger logger = Logger.getLogger(App.class);

    // main method
    public static void main(String[] args) throws Exception {
        logger.info("Starting Fabric client application...");

        // Load an existing wallet holding identities used to access the network.
        Path walletDirectory = Paths.get("/Users/olivieri/git/fabric-samples/fabcar/javascript/wallet");
        Wallet wallet = Wallet.createFileSystemWallet(walletDirectory);

        // Path to a common connection profile describing the network.
        Path networkConfigFile = Paths.get("/Users/olivieri/git/fabric-samples/first-network/connection-org1.json");

        // Configure the gateway connection used to access the network.
        Gateway.Builder builder = Gateway.createBuilder().identity(wallet, "user1").networkConfig(networkConfigFile);
        // .discovery(true);

        // Create a gateway connection
        try (Gateway gateway = builder.connect()) {

            // Obtain a smart contract deployed on the network.
            Network network = gateway.getNetwork("mychannel");
            // Contract contract = network.getContract("fabcar");
            Contract contract = network.getContract("marbles");

            byte[] result;
            UUID uuid = UUID.randomUUID();
            final String marbleName = uuid.toString();

            // Insert new marble first
            logger.info("About to create a new marble... invoking initMarble() method in chaincode...");
            result = contract.submitTransaction("initMarble", marbleName, "blue", "35", "phil collins");
            // logger.info(new String(result, StandardCharsets.UTF_8));

            // result = contract.evaluateTransaction("queryAllCars");
            logger.info("About to call readMarble() method in chaincode...");
            result = contract.evaluateTransaction("readMarble", marbleName);
            logger.info("Result from calling readMarble: " + new String(result, StandardCharsets.UTF_8));

            // Submit transactions that store state to the ledger.
            // byte[] createCarResult = contract.submitTransaction("createCar", "CAR10",
            // "VW", "Polo", "Grey", "Ricardo");
            // System.out.println(new String(createCarResult, StandardCharsets.UTF_8));

            // Evaluate transactions that query state from the ledger.
            // byte[] queryAllCarsResult = contract.evaluateTransaction("queryAllCars");
            // System.out.println(new String(queryAllCarsResult, StandardCharsets.UTF_8));

        } catch (Exception e) {
            // oops
            e.printStackTrace();
            logger.error("Something went wrong: " + e.getMessage());
        }

        // end
        logger.info("Finished executing Fabric client application...");
    }

}
