package ru.micromagicman.cryptography.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Optional;
import java.util.function.BiFunction;

/**
 * Абстрактный провайдер ключей из keystore
 * @param <T> - тип ключа
 * @param <E> - тип entity в keystore
 */
public abstract class KeyProvider<T, E> implements BiFunction<String, String, T> {

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

    protected KeyProvider( final String keyStoreLocation, final String keyStorePassword ) {
        if ( null == keyStoreLocation ) {
            throw new IllegalArgumentException( "Путь до keystore не может быть null" );
        }
        if ( null == keyStorePassword ) {
            throw new IllegalArgumentException( "Пароль от keystore не может быть null" );
        }
        this.keyStoreLocation = keyStoreLocation;
        this.keyStorePassword = keyStorePassword.toCharArray();
        this.keyStore = getKeyStore( this.keyStoreLocation, this.keyStorePassword );
    }

    protected abstract T generateNewEntity();

    protected abstract T extractEntityFromKeyStoreEntry( final String alias, final E entry );

    protected abstract KeyStore.Entry createKeyStoreEntry( final T entity );

    @SuppressWarnings( "unchecked" )
    protected Optional<E> getEntry( final String alias, final KeyStore.ProtectionParameter protection ) {
        try {
            return Optional.of( ( E ) keyStore.getEntry( alias, protection ) );
        } catch ( Exception exception ) {
            return Optional.empty();
        }
    }

    /**
     * Попытка найти ключ шифрования в keystore
     * В случае, если ключ не найден по заданному псевдониму и паролю, возвращаем null
     */
    private T findEntityOrNull( final String alias, final char[] password ) {
        try {
            return getEntry( alias, new KeyStore.PasswordProtection( password ) )
                    .map( entry -> extractEntityFromKeyStoreEntry( alias, entry ) )
                    .orElse( null );
        } catch ( Exception exception ) {
            return null;
        }
    }

    /**
     * Генерация нового секретного ключа и сохранение его в keyStore по заданному псевдониму и паролю
     */
    private T generateNewEntityAndGet( final String alias, final char[] password )
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        final T entity = generateNewEntity();
        final KeyStore.Entry entry = createKeyStoreEntry( entity );
        final KeyStore.ProtectionParameter passwordProtection = new KeyStore.PasswordProtection( password );
        keyStore.setEntry( alias, entry, passwordProtection );
        keyStore.store( new FileOutputStream( keyStoreLocation ), keyStorePassword );
        return entity;
    }

    @Override
    public T apply( final String alias, final String password ) {
        try {
            final char[] keyPasswordAsCharArray = password.toCharArray();
            final T entity = findEntityOrNull( alias, keyPasswordAsCharArray );
            return null != entity ? entity : generateNewEntityAndGet( alias, keyPasswordAsCharArray );
        } catch ( Exception exception ) {
            throw new RuntimeException( "Не удалость получить запись из keystore", exception );
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
                            "Произошла ошибка при получении доступа к keystore %s",
                            keyStoreLocation
                    ),
                    exception
            );
        }
    }
}
