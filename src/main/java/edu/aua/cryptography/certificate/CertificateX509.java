package edu.aua.cryptography.certificate;

import java.time.OffsetDateTime;
import java.util.Arrays;

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

    public static OffsetDateTime defaultValidUntil() {
        return OffsetDateTime.now().plusWeeks(1L);
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

    @Override
    public String toString() {
        return "{" +
                "version=" + version +
                ",issuerName='" + issuerName + '\'' +
                ",periodOfValidity=" + Arrays.toString(periodOfValidity) +
                ",subjectName='" + subjectName + '\'' +
                ",publicKeyInformation=" + publicKeyInformation +
                '}';
    }
}
