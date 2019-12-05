package com.mycompany.app;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Provider;

import org.hyperledger.fabric.gateway.Wallet;

public interface HSMWallet extends Wallet {
    static Wallet createHSMWallet(Provider hsmProvider, KeyStore keyStore, Path basePath) throws IOException {
        return new HSMWalletImpl(hsmProvider, keyStore, basePath);
    }

    static Wallet createHSMWallet(KeyStore keyStore, Path basePath) throws IOException {
        return new HSMWalletImpl(keyStore, basePath);
    }
} 