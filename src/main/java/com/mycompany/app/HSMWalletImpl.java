package com.mycompany.app;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonWriter;

import org.apache.log4j.Logger;
import org.apache.commons.io.FileUtils;


public class HSMWalletImpl implements HSMWallet {
    // logger
    final static Logger logger = Logger.getLogger(HSMWalletImpl.class);

    private final Path basePath;
    private final KeyStore keyStore;

    public HSMWalletImpl(final Provider securityProvider, final KeyStore keyStore, final Path path) throws IOException {
        this(keyStore, path);

        if (Security.getProvider(securityProvider.getName()) == null) {
            Security.addProvider(securityProvider);
        }
    }

    public HSMWalletImpl(final KeyStore keyStore, final Path path) throws IOException {
        this.keyStore = keyStore;

        final boolean walletExists = Files.isDirectory(path);
        if (!walletExists) {
            Files.createDirectories(path);
        }
        basePath = path;
    }

    @Override
    public void put(final String label, final Identity identity) throws IOException {
        final Path idFolder = basePath.resolve(label);
        if (!Files.isDirectory(idFolder)) {
            Files.createDirectories(idFolder);
        }
        final Path idFile = basePath.resolve(Paths.get(label, label));
        try (Writer fw = Files.newBufferedWriter(idFile)) {
            final String json = toJson(label, identity);
            fw.append(json);
        }
    }

    @Override
    public Identity get(final String label) throws IOException {
        logger.info("Getting label " + label);
        final Path idFile = basePath.resolve(Paths.get(label, label));
        if (Files.exists(idFile)) {
            try (BufferedReader fr = Files.newBufferedReader(idFile)) {
                final String contents = fr.readLine();
                return fromJson(label, contents);
            }
        }
        return null;
    }

    @Override
    public Set<String> getAllLabels() throws IOException {
        return Arrays.stream(basePath.toFile().listFiles(File::isDirectory)).map(File::getName)
                .collect(Collectors.toSet());
    }

    @Override
    public void remove(final String label) throws IOException {
        final Path idDir = basePath.resolve(label);
        if (Files.exists(idDir)) {
            FileUtils.deleteDirectory(idDir.toFile());
        }
    }

    @Override
    public boolean exists(final String label) throws IOException {
        final Path idFile = basePath.resolve(Paths.get(label, label));
        return Files.exists(idFile);
    }

    private PrivateKey loadPrivateKey(final String label) throws IOException {
        try {
            final PrivateKey privKey = (PrivateKey) keyStore.getKey(label, null);

            logger.info("Algo = " + privKey.getAlgorithm());
            if (privKey == null) {
                throw new UnrecoverableKeyException("Could not find label " + label + " in KeyStore from security provider " + keyStore.getProvider().getName());
            }
            return privKey;
        } catch(KeyStoreException e) {
            throw new IOException("KeyStore could not be loaded.", e);
        } catch(NoSuchAlgorithmException e) {
            throw new IOException("No Such Algorithm is available.", e);
        } catch(UnrecoverableKeyException e) {
            throw new IOException("Private Key could not be found for label " + label, e);
        }
    }

    private Identity fromJson(final String label, final String json) throws IOException {
        try (JsonReader reader = Json.createReader(new StringReader(json))) {
            final JsonObject idObject = reader.readObject();
            final String mspId = idObject.getString("mspid");
            final JsonObject enrollment = idObject.getJsonObject("enrollment");
            final PrivateKey pk = loadPrivateKey(label);
            final String certificate = enrollment.getJsonObject("identity").getString("certificate");
            return Identity.createIdentity(mspId, certificate, pk);
        }
    }

    private static String toJson(final String name, final Identity identity) {
        String json = null;
        final JsonObject idObject = Json.createObjectBuilder().add("name", name).add("type", "X509")
                .add("mspid", identity.getMspId())
                .add("enrollment", Json.createObjectBuilder()
                    .add("signingIdentity", name)
                    .add("identity", Json.createObjectBuilder()
                        .add("certificate", identity.getCertificate())))
                .build();

        final StringWriter writer = new StringWriter();
        try (JsonWriter jw = Json.createWriter(writer)) {
            jw.writeObject(idObject);
        }
        json = writer.toString();
        return json;
    }

}