package util;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.springframework.context.annotation.Configuration;


import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.sql.Date;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Optional;

import static util.PGPEncryption.loadResource;

@Configuration
public class PGPKeyUtil {



//
//    @Getter
//    private static String passphrase;
//
//    @Autowired
//    public PGPKeyUtil(Environment env) {
//        PGPKeyUtil.passphrase = env.getProperty("pass.phrase");
//    }


    public final static String passphrase = "hi#455n0x2";
//    private static final String passkey = passphrase;
    public static final URL privateKey = loadResource("/pgp_private_key.asc");
    public static final URL publicKey = loadResource("/pgp_public_key.asc");


    /**
     * Decrypts the public Key encrypted data using the provided private key and writes it to the output stream
     *
     * @param clearOut               the output stream to which data is to be written
     * @param pgpPrivateKey          the private key instance
     * @param publicKeyEncryptedData the public key encrypted data instance
     * @throws IOException  for IO related error
     * @throws PGPException for pgp related errors
     */
//    static void decrypt(OutputStream clearOut, PGPPrivateKey pgpPrivateKey, PGPPublicKeyEncryptedData publicKeyEncryptedData) throws IOException, PGPException {
//        PublicKeyDataDecryptorFactory decryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
//                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pgpPrivateKey);
//        InputStream decryptedCompressedIn = publicKeyEncryptedData.getDataStream(decryptorFactory);
//
//        JcaPGPObjectFactory decCompObjFac = new JcaPGPObjectFactory(decryptedCompressedIn);
//        PGPCompressedData pgpCompressedData = (PGPCompressedData) decCompObjFac.nextObject();
//
//        InputStream compressedDataStream = new BufferedInputStream(pgpCompressedData.getDataStream());
//        JcaPGPObjectFactory pgpCompObjFac = new JcaPGPObjectFactory(compressedDataStream);
//
//        Object message = pgpCompObjFac.nextObject();
//
//        if (message instanceof PGPLiteralData) {
//            PGPLiteralData pgpLiteralData = (PGPLiteralData) message;
//            InputStream decDataStream = pgpLiteralData.getInputStream();
//            IOUtils.copy(decDataStream, clearOut);
//            clearOut.close();
//        } else if (message instanceof PGPOnePassSignatureList) {
//            // Process the signature list
//            PGPOnePassSignatureList signatureList = (PGPOnePassSignatureList) message;
//            PGPOnePassSignature onePassSignature = signatureList.get(0);
//
//            // Get the next object, which should be the literal data
//            PGPLiteralData literalData = (PGPLiteralData) pgpCompObjFac.nextObject();
//            InputStream decDataStream = literalData.getInputStream();
//
//            // Find the public key to verify the signature
//            PGPPublicKey senderPublicKey = getPublicKey(publicKey.openStream());
//            if (senderPublicKey == null) {
//                throw new PGPException("Signature key ID does not match any public key in the keyring.");
//            }
//
//            // Initialize the signature verifier
//            onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), senderPublicKey);
//
//            // Verify each byte of data while writing it to the output stream
//            byte[] buffer = new byte[1024];
//            int len;
//            while ((len = decDataStream.read(buffer)) > 0) {
//                clearOut.write(buffer, 0, len);
//                onePassSignature.update(buffer, 0, len); // Update signature verification
//            }
//
//            clearOut.close();
//
//            // Finalize the signature verification
//            PGPSignatureList signatureList2 = (PGPSignatureList) pgpCompObjFac.nextObject();
//            PGPSignature signature = signatureList2.get(0);
//
//            if (!onePassSignature.verify(signature)) {
//                throw new PGPException("Signature verification failed.");
//            }
////            throw new PGPException("Encrypted message contains a signed message not literal data");
//        } else {
//            throw new PGPException("Message is not a simple encrypted file - Type Unknown");
//        }
//        // Performing Integrity check
//        if (publicKeyEncryptedData.isIntegrityProtected()) {
//            if (!publicKeyEncryptedData.verify()) {
//                throw new PGPException("Message failed integrity check");
//            }
//        }
//    }

    static void decrypt(OutputStream clearOut, PGPPrivateKey pgpPrivateKey, PGPPublicKeyEncryptedData publicKeyEncryptedData)
            throws IOException, PGPException {
        PublicKeyDataDecryptorFactory decryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider("BC").build(pgpPrivateKey);
        InputStream decryptedCompressedIn = publicKeyEncryptedData.getDataStream(decryptorFactory);

        JcaPGPObjectFactory decCompObjFac = new JcaPGPObjectFactory(decryptedCompressedIn);
        Object firstObject = decCompObjFac.nextObject();

        if (firstObject instanceof PGPCompressedData) {
            // Handle compressed data
            PGPCompressedData pgpCompressedData = (PGPCompressedData) firstObject;
            InputStream compressedDataStream = new BufferedInputStream(pgpCompressedData.getDataStream());
            JcaPGPObjectFactory pgpCompObjFac = new JcaPGPObjectFactory(compressedDataStream);
            processDecryptedObject(clearOut, pgpCompObjFac);
        } else if (firstObject instanceof PGPLiteralData) {
            // If data is not compressed, process it directly
            processLiteralData((PGPLiteralData) firstObject, clearOut);
        } else {
            throw new PGPException("Unexpected PGP object type: " + firstObject.getClass().getName());
        }

        // Perform integrity check
        if (publicKeyEncryptedData.isIntegrityProtected() && !publicKeyEncryptedData.verify()) {
            throw new PGPException("Message failed integrity check");
        }
    }

    // Helper method to process decrypted data, either literal or signed
    private static void processDecryptedObject(OutputStream clearOut, JcaPGPObjectFactory pgpCompObjFac)
            throws IOException, PGPException {
        Object message = pgpCompObjFac.nextObject();

        if (message instanceof PGPLiteralData) {
            // Directly handle literal data
            processLiteralData((PGPLiteralData) message, clearOut);
        } else if (message instanceof PGPOnePassSignatureList) {
            // Process signature
            handleSignatureVerification(clearOut, pgpCompObjFac, (PGPOnePassSignatureList) message);
        } else {
            throw new PGPException("Unexpected PGP object type after decompression.");
        }
    }

    // Process literal data directly
    private static void processLiteralData(PGPLiteralData literalData, OutputStream clearOut) throws IOException {
        try (InputStream decDataStream = literalData.getInputStream()) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = decDataStream.read(buffer)) > 0) {
                clearOut.write(buffer, 0, len);
            }
        }
        clearOut.close();
    }

    // Handle signature verification
    private static void handleSignatureVerification(OutputStream clearOut, JcaPGPObjectFactory pgpCompObjFac, PGPOnePassSignatureList signatureList)
            throws IOException, PGPException {
        PGPOnePassSignature onePassSignature = signatureList.get(0);

        // Retrieve the sender's public key for verification
        PGPPublicKey senderPublicKey = getPublicKey(publicKey.openStream());
//        PGPPublicKey senderPublicKey = publicKeyRingCollection.getPublicKey(onePassSignature.getKeyID());
        if (senderPublicKey == null) {
            throw new PGPException("Signature key ID does not match any public key in the keyring.");
        }

        // Initialize the signature verifier
        onePassSignature.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), senderPublicKey);

        // Get the next object which should be the literal data
        PGPLiteralData literalData = (PGPLiteralData) pgpCompObjFac.nextObject();
        try (InputStream decDataStream = literalData.getInputStream()) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = decDataStream.read(buffer)) > 0) {
                clearOut.write(buffer, 0, len);
                onePassSignature.update(buffer, 0, len); // Update signature verification
            }
        }

        // Finalize the signature verification
        PGPSignatureList signatureList2 = (PGPSignatureList) pgpCompObjFac.nextObject();
        PGPSignature signature = signatureList2.get(0);

        if (!onePassSignature.verify(signature)) {
            throw new PGPException("Signature verification failed.");
        }
        clearOut.close();
    }



    /**
     * Gets the public key from the key input stream
     *
     * @param keyInputStream the key input stream
     * @return a PGPPublic key instance
     * @throws IOException  for IO related errors
     * @throws PGPException PGPException for pgp related errors
     */
    static PGPPublicKey getPublicKey(InputStream keyInputStream) throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPublicKeyRings = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(keyInputStream), new JcaKeyFingerprintCalculator());
        Iterator<PGPPublicKeyRing> keyRingIterator = pgpPublicKeyRings.getKeyRings();
        while (keyRingIterator.hasNext()) {
            PGPPublicKeyRing pgpPublicKeyRing = keyRingIterator.next();
            Optional<PGPPublicKey> pgpPublicKey = extractPGPKeyFromRing(pgpPublicKeyRing);
            if (pgpPublicKey.isPresent()) {
                return pgpPublicKey.get();
            }
        }
        throw new PGPException("Invalid public key");
    }

    /**
     * Copies "length" amount of data from the input stream and writes it pgp literal data to the provided output stream
     *
     * @param outputStream the output stream to which data is to be written
     * @param in           the input stream from which data is to be read
     * @param length       the length of data to be read
     * @param bufferSize   the buffer size, as it uses buffer to speed up copying
     * @throws IOException for IO related errors
     */
    static void copyAsLiteralData(OutputStream outputStream, InputStream in, long length, int bufferSize, PGPSignatureGenerator signatureGenerator) throws IOException {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(outputStream, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE,
                Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC)), new byte[bufferSize]);
        byte[] buff = new byte[bufferSize];
        try (in) {
            int len;
            long totalBytesWritten = 0L;
            while (totalBytesWritten <= length && (len = in.read(buff)) > 0) {
                pOut.write(buff, 0, len);
                signatureGenerator.update(buff, 0, len);
                totalBytesWritten += len;
            }
            pOut.close();
            signatureGenerator.generate().encode(outputStream);
        } catch (PGPException e) {
            throw new RuntimeException(e);
        } finally {
            // Clearing buffer
            Arrays.fill(buff, (byte) 0);
            // Closing inputstream
        }
    }

    private static Optional<PGPPublicKey> extractPGPKeyFromRing(PGPPublicKeyRing pgpPublicKeyRing) {
        for (PGPPublicKey publicKey : pgpPublicKeyRing) {
            if (publicKey.isEncryptionKey()) {
                return Optional.of(publicKey);
            }
        }
        return Optional.empty();
    }

    /**
     * Extracts a PGPPrivateKey from an InputStream containing the private key, using the specified passphrase.
     *
     * @param privateKeyIn InputStream with the private key (can be armored or binary).
     * @param passphrase    Passphrase for the private key.
     * @return              The unlocked PGPPrivateKey.
     * @throws IOException, PGPException
     */
    public static PGPPrivateKey getPrivateKey(InputStream privateKeyIn, char[] passphrase)
            throws IOException, PGPException {
        // Open the input stream with possible Armored encoding
        InputStream decodedKeyIn = PGPUtil.getDecoderStream(privateKeyIn);

        // Initialize PGP object factory to parse the key ring
        PGPSecretKeyRingCollection pgpSecKeyRingCollection = new PGPSecretKeyRingCollection(
                decodedKeyIn, new JcaKeyFingerprintCalculator());

        // Iterate through secret keys to find one suitable for signing
        Iterator<PGPSecretKeyRing> keyRingIterator = pgpSecKeyRingCollection.getKeyRings();
        while (keyRingIterator.hasNext()) {
            PGPSecretKeyRing keyRing = keyRingIterator.next();
            Iterator<PGPSecretKey> keyIterator = keyRing.getSecretKeys();

            while (keyIterator.hasNext()) {
                PGPSecretKey secretKey = keyIterator.next();

                // Look for a key that can be used for signing
                if (secretKey.isSigningKey()) {
                    PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder()
                            .setProvider("BC")
                            .build(passphrase);

                    return secretKey.extractPrivateKey(decryptor);
                }
            }
        }

        throw new PGPException("No signing key found in the provided key ring.");
    }

}