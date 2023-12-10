package edu.aua.cryptography.certificate;

import java.time.OffsetDateTime;

public class CertificateX509 {
    private final int version;
    private final String issuerName;
    private final OffsetDateTime[] periodOfValidity;
    private final String subjectName;
    private final SubjectPublicKeyInformation publicKeyInformation;
    private SignatureInformation signatureInformation;

    public CertificateX509(int version, String issuerName, OffsetDateTime[] periodOfValidity, String subjectName, SubjectPublicKeyInformation publicKeyInformation) {
        this.version = version;
        this.issuerName = issuerName;
        this.periodOfValidity = periodOfValidity;
        this.subjectName = subjectName;
        this.publicKeyInformation = publicKeyInformation;
    }

    public int getVersion() {
        return version;
    }

    public String getIssuerName() {
        return issuerName;
    }

    public OffsetDateTime[] getPeriodOfValidity() {
        return periodOfValidity;
    }

    public String getSubjectName() {
        return subjectName;
    }

    public SubjectPublicKeyInformation getPublicKeyInformation() {
        return publicKeyInformation;
    }

    public SignatureInformation getSignatureInformation() {
        return signatureInformation;
    }

    public void setSignatureInformation(SignatureInformation signatureInformation) {
        this.signatureInformation = signatureInformation;
    }
}
