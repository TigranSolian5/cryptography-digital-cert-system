package edu.aua.cryptography;

import edu.aua.cryptography.certificate.authority.CertificateAuthority;
import edu.aua.cryptography.cipher.core.Cipher;
import edu.aua.cryptography.cipher.core.CipherFactory;
import edu.aua.cryptography.cipher.core.CipherType;
import edu.aua.cryptography.signature.core.DigitalSignatureType;
import edu.aua.cryptography.user.User;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Application {

    static {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    public static void main(String[] args) {
        var cipherFactory = new CipherFactory();
        var rsaCipher = cipherFactory.getInstance(CipherType.RSA);

        var bob = new User("bob", CipherType.RSA);
        var alice = new User("alice", CipherType.RSA);

        var ca = createExampleCA();

        bob.registerPublicKeyCertificateToAuthority(ca);
        alice.registerPublicKeyCertificateToAuthority(ca);

        var secretKey = bob.generateSymmetricKeyForSubject(CipherType.AES_256, "alice");
        var aliceCertificate = bob.queryForCertificateOfSubject(ca, "alice", 1);
        System.out.println("aliceCertificate: " + aliceCertificate);

        var alicePK = aliceCertificate.getPublicKeyInformation().key();
        var encryptedMessage = rsaCipher.apply(Cipher.OpMode.ENCRYPT, secretKey, alicePK, bob.getAsymmetricKeyInformation().getPrivateKey());
        var decryptedMessage = rsaCipher.apply(Cipher.OpMode.DECRYPT, encryptedMessage, bob.getAsymmetricKeyInformation().getPublicKey(), alice.getAsymmetricKeyInformation().getPrivateKey());
    }

    private static CertificateAuthority createExampleCA() {
        KeyPairGenerator keyPairGen;
        try {
            keyPairGen = KeyPairGenerator.getInstance("ELGAMAL", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new RuntimeException(ex);
        }
        keyPairGen.initialize(512);

        var keyPair = keyPairGen.generateKeyPair();

        return new CertificateAuthority(
                "yerevan_central",
                keyPair.getPrivate().getEncoded(),
                keyPair.getPublic().getEncoded(),
                DigitalSignatureType.ELGAMAL
        );
    }
}
