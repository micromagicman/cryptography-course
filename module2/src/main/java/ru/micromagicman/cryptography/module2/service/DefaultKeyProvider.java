package ru.micromagicman.cryptography.module2.service;

import ru.micromagicman.cryptography.module2.CommonConstants;
import ru.micromagicman.cryptography.service.KeyProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

/**
 * Провайдер ключей из keystore
 */
public class DefaultKeyProvider extends KeyProvider<SecretKey, KeyStore.SecretKeyEntry> {

    public DefaultKeyProvider( final String keyStoreLocation, final String keyStorePassword ) {
        super( keyStoreLocation, keyStorePassword );
    }

    @Override
    protected SecretKey generateNewEntity() {
        try {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance( CommonConstants.Algorithms.KEY_GENERATION );
            keyGenerator.init( CommonConstants.SYMMETRIC_KEY_SIZE );
            return keyGenerator.generateKey();
        } catch ( NoSuchAlgorithmException exception ) {
            throw new RuntimeException( "Произошла ошибка при генерации ключа симметричного шифрования", exception );
        }
    }

    @Override
    protected SecretKey extractEntityFromKeyStoreEntry( final String alias, final KeyStore.SecretKeyEntry entry ) {
        return entry.getSecretKey();
    }

    @Override
    protected KeyStore.Entry createKeyStoreEntry( final SecretKey entity ) {
        return new KeyStore.SecretKeyEntry( entity );
    }
}
