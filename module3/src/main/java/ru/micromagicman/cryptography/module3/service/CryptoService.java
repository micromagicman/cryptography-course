package ru.micromagicman.cryptography.module3.service;

import ru.micromagicman.cryptography.module3.CommonConstants;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * Сервис для шифрования/дешифрования произвольных текстовых сообщений
 */
public class CryptoService {

    /**
     * Абстрактный провайдер ключей шифрования
     */
    private final BiFunction<String, String, KeyPair> keyPairProvider;

    /**
     * Операция асимметричного шифрования
     */
    public enum Operation {

        /**
         * Шифрование
         */
        ENCRYPT( Cipher.ENCRYPT_MODE, KeyPair::getPublic ),

        /**
         * Дешифрование
         */
        DECRYPT( Cipher.DECRYPT_MODE, KeyPair::getPrivate );

        /**
         * Код операции
         */
        private final int code;

        private final Function<KeyPair, Key> keyExtractor;

        Operation( final int mode, final Function<KeyPair, Key> keyExtractor ) {
            this.code = mode;
            this.keyExtractor = keyExtractor;
        }

        /**
         * Проведение операции для конкретного шифра
         * Метод обеспечивает синхронизированный доступ к объекту cipher для проведения операции
         */
        public byte[] perform( final byte[] data, final Cipher cipher, final KeyPair keyPair )
                throws Exception {
            cipher.init( code, keyExtractor.apply( keyPair ) );
            return cipher.doFinal( data );
        }
    }

    public CryptoService( final BiFunction<String, String, KeyPair> keyPairProvider ) {
        this.keyPairProvider = keyPairProvider;
    }

    /**
     * Зашифровать текст
     *
     *@param keyAlias- псевдоним ключа шифрования в keystore
     *@param keyPassword- пароль от ключа шифрования в keystore
     */
    public byte[] encrypt( final String plainText, final String keyAlias, final String keyPassword ) {
        return encrypt( plainText.getBytes( StandardCharsets.UTF_8 ), keyAlias, keyPassword );
    }

    /**
     * Зашифровать текст, передаваемый в качестве массива байт
     *
     *@param keyAlias- псевдоним ключа шифрования в keystore
     *@param keyPassword- пароль от ключа шифрования в keystore
     */
    public byte[] encrypt( final byte[] plainText, final String keyAlias, final String keyPassword ) {
        return operate( plainText, Operation.ENCRYPT, keyAlias, keyPassword );
    }

    /**
     * Расшифровать шифртекст
     *
     *@param keyAlias- псевдоним ключа шифрования в keystore
     *@param keyPassword- пароль от ключа шифрования в keystore
     */
    public byte[] decrypt( final String cipherText, final String keyAlias, final String keyPassword ) {
        return decrypt( cipherText.getBytes( StandardCharsets.UTF_8 ), keyAlias, keyPassword );
    }

    /**
     * Расшифровать шифртекст, передаваемый в качестве массива байт
     *
     *@param keyAlias- псевдоним ключа шифрования в keystore
     *@param keyPassword- пароль от ключа шифрования в keystore
     */
    public byte[] decrypt( final byte[] cipherText, final String keyAlias, final String keyPassword ) {
        return operate( cipherText, Operation.DECRYPT, keyAlias, keyPassword );
    }

    /**
     * Совершение операции шифрования/дешифрования в зависимости от переданного режима
     *
     *@param data- преобразуемые данные
     *@param operation- операция (шифровать/дешифровать)
     *@param keyAlias- псевдоним ключа шифрования в keystore
     *@param keyPassword- пароль от ключа шифрования в keystore
     */
    private byte[] operate( final byte[] data, final Operation operation, final String keyAlias, final String keyPassword ) {
        try {
            final KeyPair keyPair = keyPairProvider.apply( keyAlias, keyPassword );
            return operation.perform( data, createCipher(), keyPair );
        } catch ( Exception exception ) {
            throw new RuntimeException( String.format( CommonConstants.MessageTemplates.OPERATION_ERROR, operation.name() ),
                    exception );
        }
    }

    /**
     * Инициализация симметричного шифра для преобразования текста
     */
    private Cipher createCipher() {
        try {
            return Cipher.getInstance( CommonConstants.Algorithms.ASYMMETRIC_ALGORITHM_NAME );
        } catch ( Exception exception ) {
            throw new RuntimeException(
                    String.format(
                            CommonConstants.MessageTemplates.ALGORITHM_INIT_ERROR,
                            CommonConstants.Algorithms.ASYMMETRIC_ALGORITHM_NAME
                    ),
                    exception
            );
        }
    }
}
