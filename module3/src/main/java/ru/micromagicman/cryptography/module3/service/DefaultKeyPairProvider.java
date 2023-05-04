package ru.micromagicman.cryptography.module3.service;

import ru.micromagicman.cryptography.module3.CommonConstants;
import ru.micromagicman.cryptography.service.KeyProvider;
import ru.micromagicman.cryptography.utils.CertificateUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;

/**
 * Провайдер пары публичный/приватный ключ из keystore
 */
public class DefaultKeyPairProvider extends KeyProvider<KeyPair, KeyStore.PrivateKeyEntry> {

    public DefaultKeyPairProvider( final String keyStoreLocation, final String keyStorePassword ) {
        super( keyStoreLocation, keyStorePassword );
    }

    @Override
    protected KeyPair generateNewEntity() {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator
                    .getInstance( CommonConstants.Algorithms.KEY_GENERATION );
            keyPairGenerator.initialize( CommonConstants.ASYMMETRIC_KEY_SIZE );
            return keyPairGenerator.generateKeyPair();
        } catch ( NoSuchAlgorithmException exception ) {
            throw new RuntimeException( "Произошла ошибка при генерации пары публичного/приватного ключей", exception );
        }
    }

    @Override
    protected KeyPair extractEntityFromKeyStoreEntry( final String alias, final KeyStore.PrivateKeyEntry entry ) {
        return new KeyPair( entry.getCertificate().getPublicKey(), entry.getPrivateKey() );
    }

    @Override
    protected KeyStore.Entry createKeyStoreEntry( final KeyPair entity ) {
        try {
            final Certificate selfSigned = CertificateUtils.createSelfSigned( "TEST", entity,
                    CommonConstants.YEAR_MILLIS );
            return new KeyStore.PrivateKeyEntry( entity.getPrivate(), new Certificate[]{ selfSigned } );
        } catch ( Exception exception ) {
            throw new RuntimeException( "Произошла ошибка при сохранении пары публичный/приватный ключ в keystore",
                    exception );
        }
    }
}
