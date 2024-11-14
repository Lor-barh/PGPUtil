package util;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.net.URL;
import java.security.SecureRandom;
import java.security.Security;
import java.util.*;

import static util.PGPKeyUtil.passphrase;
import static util.PGPKeyUtil.publicKey;


@Getter
@Builder
@AllArgsConstructor
public class PGPEncryption {

    static {
        // Add Bouncy castle to JVM
        if (Objects.isNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME))) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Builder.Default
    private static int compressionAlgorithm = CompressionAlgorithmTags.ZIP;
    @Builder.Default
    private static int symmetricKeyAlgorithm = SymmetricKeyAlgorithmTags.AES_128;
    @Builder.Default
    private static boolean armor = true;
    @Builder.Default
    private static boolean withIntegrityCheck = true;
    @Builder.Default
    private static int bufferSize = 1 << 16;

    static URL loadResource(String resourcePath) {
        return Optional.ofNullable(PGPEncryption.class.getResource(resourcePath))
                .orElseThrow(() -> new IllegalArgumentException("Resource not found"));
    }


    public static void encrypt(OutputStream encryptOut, InputStream clearIn, long length, InputStream publicKeyIn)
            throws IOException, PGPException {
        PGPCompressedDataGenerator compressedDataGenerator =
                new PGPCompressedDataGenerator(compressionAlgorithm);
        PGPEncryptedDataGenerator pgpEncryptedDataGenerator = new PGPEncryptedDataGenerator(

                new JcePGPDataEncryptorBuilder(symmetricKeyAlgorithm)
                        .setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom())
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        );

        pgpEncryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(
                PGPKeyUtil.getPublicKey(publicKeyIn)));
        if (armor) {
            encryptOut = new ArmoredOutputStream(encryptOut);
        }

        // Set up signing
        PGPPrivateKey privateKey = PGPKeyUtil.getPrivateKey(PGPKeyUtil.privateKey.openStream(), passphrase.toCharArray());
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(privateKey.getPublicKeyPacket().getAlgorithm(), HashAlgorithmTags.SHA256)
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
        );
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

        OutputStream cipherOutStream = pgpEncryptedDataGenerator.open(encryptOut, new byte[bufferSize]);

        // Open compressed stream and sign data
        OutputStream compressedOut = compressedDataGenerator.open(cipherOutStream);
        signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

        PGPKeyUtil.copyAsLiteralData(compressedOut, clearIn, length, bufferSize,signatureGenerator);

        // Complete the signature
        signatureGenerator.generate().encode(compressedOut);
        compressedDataGenerator.close();
        cipherOutStream.close();
        encryptOut.close();
    }


    public static byte[] encrypt(byte[] clearData) throws PGPException, IOException {
        InputStream pubicKeyIn = publicKey.openStream();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(clearData);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        encrypt(outputStream, inputStream, clearData.length, pubicKeyIn);
        return outputStream.toByteArray();
    }


}