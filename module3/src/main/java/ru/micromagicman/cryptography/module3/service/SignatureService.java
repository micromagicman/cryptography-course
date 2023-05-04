package ru.micromagicman.cryptography.module3.service;

import ru.micromagicman.cryptography.module3.CommonConstants;

import java.security.*;
import java.util.function.BiFunction;

/**
 * Сервис для работы с цифровыми подписями
 */
public class SignatureService {

    /**
     * Провайдер пары публичный/приватный ключ из keystore
     */
    private final BiFunction<String, String, KeyPair> keyPairProvider;

    public SignatureService( final BiFunction<String, String, KeyPair> keyPairProvider ) {
        this.keyPairProvider = keyPairProvider;
    }

    /**
     * Создание цифровой подписи для данных в виде массива байт
     */
    public byte[] create( final String keyAlias, final String keyPassword, final byte[] source ) {
        try {
            final Signature signature = createSignature();
            signature.initSign( keyPairProvider.apply( keyAlias, keyPassword ).getPrivate() );
            signature.update( source );
            return signature.sign();
        } catch ( Exception exception ) {
            throw new RuntimeException( "Произошла ошибка при попытке создания цифровой подписи", exception );
        }
    }

    /**
     * Проверка цифровой подписи
     */
    public boolean verify(
            final String keyAlias,
            final String keyPassword,
            final byte[] sourceDataBytes,
            final byte[] signatureBytes ) {
        try {
            Signature signature = createSignature();
            signature.initVerify( keyPairProvider.apply( keyAlias, keyPassword ).getPublic() );
            signature.update( sourceDataBytes );
            return signature.verify( signatureBytes );
        } catch ( Exception exception ) {
            throw new RuntimeException( "Произошла ошибка при попытке верификации цифровой подписи", exception );
        }
    }

    private Signature createSignature() {
        try {
            return Signature.getInstance( CommonConstants.Algorithms.SIGNATURE_ALGORITHM );
        } catch ( NoSuchAlgorithmException exception ) {
            throw new RuntimeException( "Ошибка при создании объекта цифоровой подписи", exception );
        }
    }
}
