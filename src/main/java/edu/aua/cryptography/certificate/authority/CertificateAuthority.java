package edu.aua.cryptography.certificate.authority;

import edu.aua.cryptography.certificate.CertificateX509;
import edu.aua.cryptography.certificate.SignatureInformation;
import edu.aua.cryptography.hash.core.Hash;
import edu.aua.cryptography.signature.core.DigitalSignature;
import edu.aua.cryptography.signature.core.DigitalSignatureType;

import java.nio.ByteBuffer;
import java.time.OffsetDateTime;
import java.util.HashSet;
import java.util.NoSuchElementException;
import java.util.Set;

public class CertificateAuthority {

    private final String name;
    private final byte[] privateKey;
    private final byte[] publicKey;
    private final DigitalSignatureType signatureType;
    private final DigitalSignature signatureInstance;
    private final Set<CertificateX509> certificates = new HashSet<>();

    public CertificateAuthority(final String name, final byte[] privateKey, final byte[] publicKey, final DigitalSignatureType signatureType) {
        this.name = name;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.signatureType = signatureType;
        this.signatureInstance = signatureType.getSignature();
    }

    public void registerCertificate(final RegisterCertificateProps props) {
        var subjectName = props.subjectName();
        var version = certificates.stream()
                .filter(certificate -> certificate.getSubjectName().equals(subjectName))
                .findFirst()
                .map(certificate -> certificate.getVersion() + 1)
                .orElse(1);
        var periodOfValidity = new OffsetDateTime[] {OffsetDateTime.now(), props.validUntil()};
        var publicKeyInformation = props.publicKeyInformation();

        var certificate = new CertificateX509(version, name, periodOfValidity, subjectName, publicKeyInformation);
        var signatureInformation = new SignatureInformation(
                signatureInstance.sign(ByteBuffer.allocate(4).putInt(certificate.hashCode()).array(), publicKey, privateKey),
                signatureType.name()
        );
        certificate.setSignatureInformation(signatureInformation);

        certificates.add(certificate);
    }

    public CertificateX509 getForSubject(final String subjectName) {
        return certificates.stream()
                .filter(certificate -> certificate.getSubjectName().equals(subjectName))
                .findFirst()
                .orElseThrow(() -> new NoSuchElementException("No such certificate found for subject"));
    }

    public byte[] getPublicKey() {
        return publicKey;
    }
}
