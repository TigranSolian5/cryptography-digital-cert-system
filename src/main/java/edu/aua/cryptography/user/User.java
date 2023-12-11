package edu.aua.cryptography.user;

import edu.aua.cryptography.certificate.CertificateX509;
import edu.aua.cryptography.certificate.SubjectPublicKeyInformation;
import edu.aua.cryptography.certificate.authority.CertificateAuthority;
import edu.aua.cryptography.certificate.authority.RegisterCertificateProps;
import edu.aua.cryptography.cipher.core.CipherType;
import edu.aua.cryptography.signature.core.DigitalSignatureFactory;

import javax.crypto.KeyGenerator;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

public class User {

    private final String subjectName;
    private AsymmetricKeyInformation asymmetricKeyInformation;
    private Set<SymmetricKeyInformation> symmetricKeyInformation = new HashSet<>();
    private final DigitalSignatureFactory digitalSignatureFactory;

    public User(final String subjectName, final CipherType asymmetricCipherType) {
        this.subjectName = subjectName;
        this.digitalSignatureFactory = new DigitalSignatureFactory();
        generateKeysForCipherType(asymmetricCipherType);
    }

    public void registerPublicKeyCertificateToAuthority(final CertificateAuthority ca) {
        var publicKeyInfo = new SubjectPublicKeyInformation(
                asymmetricKeyInformation.getPublicKey(),
                asymmetricKeyInformation.getAlgorithm()
        );
        var props = new RegisterCertificateProps(
                subjectName,
                CertificateX509.defaultValidUntil(),
                publicKeyInfo
        );

        ca.registerCertificate(props);
    }

    public CertificateX509 queryForCertificateOfSubject(final CertificateAuthority ca, final String subject, final int version) {
        var certificate = ca.getForSubject(subject, version);
        validateCertificate(certificate, ca);

        return certificate;
    }

    private void generateKeysForCipherType(final CipherType asymmetricCipherType) {
        if (asymmetricCipherType != CipherType.RSA) {
            throw new UnsupportedOperationException("We don't yet know how to generate keys for other algorithms besides RSA");
        }

        var algorithm = "RSA";
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
            keyGen.initialize(2048);

            var keyPair = keyGen.genKeyPair();
            asymmetricKeyInformation = new AsymmetricKeyInformation(
                    keyPair.getPublic().getEncoded(),
                    keyPair.getPrivate().getEncoded(),
                    algorithm
            );
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private void validateCertificate(final CertificateX509 certificate, final CertificateAuthority ca) {
        var signatureInfo = certificate.getSignatureInformation();
        var signature = signatureInfo.signature();
        var signatureAlgorithm = digitalSignatureFactory.getSignature(signatureInfo.signatureAlgorithm());

        var isValid = signatureAlgorithm.validate(
                signature,
                certificate.toString().getBytes(),
                ca.getPublicKey()
        );
        if (!isValid) {
            throw new IllegalStateException("Invalid certificate");
        }
    }

    private byte[] getSymmetricKeyForSubject(final String subject) {
        return symmetricKeyInformation.stream()
                .filter(info -> info.recipientId().equals(subject))
                .findFirst()
                .map(SymmetricKeyInformation::symmetricKey)
                .orElse(null);
    }

    public byte[] generateSymmetricKeyForSubject(final CipherType cipherType, final String subject) {
        if (cipherType != CipherType.AES_256) {
            throw new UnsupportedOperationException("We don't yet know how to generate keys for other algorithms besides AES_256");
        }

        try {
            var keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            var key = keyGen.generateKey().getEncoded();

            var newSymmetricKeyInfo = new SymmetricKeyInformation(key, subject);
            symmetricKeyInformation.add(newSymmetricKeyInfo);

            return newSymmetricKeyInfo.symmetricKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public AsymmetricKeyInformation getAsymmetricKeyInformation() {
        return asymmetricKeyInformation;
    }
}
