package ru.micromagicman.cryptography.utils;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Random;

public final class CertificateUtils {

    private static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String COMMON_NAME_PREFIX = "CN=";

    public static Certificate createSelfSigned( final String commonName, final KeyPair keyPair, final long expiryTimeMillis )
            throws CertificateException, OperatorCreationException, NoSuchAlgorithmException {
        return new JcaX509CertificateConverter()
                .getCertificate(
                        newBuilder( commonName, keyPair.getPublic(), expiryTimeMillis )
                                .build(
                                        new JcaContentSignerBuilder( SIGNATURE_ALGORITHM )
                                                .build( keyPair.getPrivate() )
                                )
                );
    }

    private static X509v3CertificateBuilder newBuilder( final String name, final PublicKey publicKey, final long expiryTimeMillis )
            throws NoSuchAlgorithmException {
        final long nowMillis = System.currentTimeMillis();
        final long seed = System.nanoTime() ^ ( name.hashCode() * 31L + ( expiryTimeMillis << 32 ) * 57L );
        final Random secureRandom = SecureRandom.getInstance( SECURE_RANDOM_ALGORITHM );
        secureRandom.setSeed( seed );
        return new JcaX509v3CertificateBuilder(
                new X500Name( COMMON_NAME_PREFIX + name ),
                BigInteger.valueOf( secureRandom.nextInt() ),
                new Date( nowMillis ),
                new Date( nowMillis + expiryTimeMillis ),
                new X500Name( COMMON_NAME_PREFIX + name ),
                publicKey
        );
    }
}
