package edu.aua.cryptography.certificate.authority;

import edu.aua.cryptography.certificate.SubjectPublicKeyInformation;

import java.time.OffsetDateTime;

public record RegisterCertificateProps(
        String subjectName,
        OffsetDateTime validUntil,
        SubjectPublicKeyInformation publicKeyInformation
) {}
