package ru.micromagicman.cryptography.module2.service;

import ru.micromagicman.cryptography.module2.CommonConstants;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Optional;
import java.util.function.BiFunction;

/**
 * Провайдер ключей из keystore
 */
public class DefaultKeyProvider implements BiFunction<String, String, Key> {

    /**
     * Путь до файла keystore
     */
    private final String keyStoreLocation;

    /**
     * Пароль от keystore
     */
    private final char[] keyStorePassword;

    /**
     * Объект для манипуляции ключами в рамках keystore
     */
    private final KeyStore keyStore;

    public DefaultKeyProvider( final String keyStoreLocation, final String keyStorePassword ) {
        if ( null == keyStoreLocation ) {
            throw new IllegalArgumentException( "Путь до keystore не может быть null" );
        }
        if ( null == keyStorePassword ) {
            throw new IllegalArgumentException( "Пароль от keystore не может быть null" );
        }
        this.keyStoreLocation = keyStoreLocation;
        this.keyStorePassword = keyStorePassword.toCharArray();
        this.keyStore =getKeyStore( this.keyStoreLocation, this.keyStorePassword );
    }

    @Override
    public Key apply( final String keyAlias, final String keyPassword ) {
        try {
            final char[] keyPasswordAsCharArray = keyPassword.toCharArray();
            final SecretKey secretKey = findSecretKeyOrNull( keyAlias, keyPasswordAsCharArray );
            return null != secretKey ? secretKey : generateNewSecretKeyAndGet( keyAlias, keyPasswordAsCharArray );
        } catch ( Exception exception ) {
            throw new RuntimeException();
        }
    }

    /**
     * Генерация нового секретного ключа и сохранение его в keyStore по заданному псевдониму и паролю
     */
    private SecretKey generateNewSecretKeyAndGet( final String keyAlias, final char[] keyPassword )
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        final SecretKey secretKey = generateKey();
        KeyStore.SecretKeyEntry secret = new KeyStore.SecretKeyEntry( secretKey );
        KeyStore.ProtectionParameter password = new KeyStore.PasswordProtection( keyPassword );
        keyStore.setEntry( keyAlias, secret, password );
        keyStore.store( new FileOutputStream( keyStoreLocation ), keyStorePassword );
        return secretKey;
    }

    /**
     * Попытка найти ключ шифрования в keystore
     * В случае, если ключ не найден по заданному псевдониму и паролю, возвращаем null
     */
    private SecretKey findSecretKeyOrNull( final String keyAlias, final char[] keyPassword ) {
        try {
            return Optional.ofNullable( keyStore.getEntry( keyAlias, new KeyStore.PasswordProtection( keyPassword ) ) )
                    .map( entry -> ( KeyStore.SecretKeyEntry ) entry )
                    .map( KeyStore.SecretKeyEntry::getSecretKey )
                    .orElse( null );
        } catch ( Exception exception ) {
            return null;
        }
    }

    /**
     * Получение объекта для доступа к keyStore
     */
    private static KeyStore getKeyStore( final String keyStoreLocation, final char[] keyStorePassword ) {
        try {
            final File file = new File( keyStoreLocation );
            final KeyStore keyStore = KeyStore.getInstance( KeyStore.getDefaultType() );
            if ( file.exists() ) {
                keyStore.load( new FileInputStream( file ), keyStorePassword );
            } else {
                keyStore.load( null, null );
                keyStore.store( new FileOutputStream( file ), keyStorePassword );
            }
            return keyStore;
        } catch ( Exception exception ) {
            throw new RuntimeException(
                    String.format(
                            CommonConstants.MessageTemplates.KEYSTORE_INIT_ERROR,
                            keyStoreLocation
                    ),
                    exception
            );
        }
    }

    /**
     * Генерация секретного симметричного ключа
     */
    private SecretKey generateKey() {
        try {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance( CommonConstants.Algorithms.KEY_GENERATION );
            keyGenerator.init( CommonConstants.SYMMETRIC_KEY_SIZE );
            return keyGenerator.generateKey();
        } catch ( NoSuchAlgorithmException exception ) {
            throw new RuntimeException( "Произошла ошибка при генерации ключа симметричного шифрования", exception );
        }
    }
}
