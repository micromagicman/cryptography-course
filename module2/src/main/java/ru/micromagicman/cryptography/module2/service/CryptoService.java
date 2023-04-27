package ru.micromagicman.cryptography.module2.service;

import ru.micromagicman.cryptography.module2.CommonConstants;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.function.BiFunction;

/**
 * Сервис для шифрования/дешифрования произвольных текстовых сообщений
 */
public class CryptoService {

    /**
     * Симметричный шифр, используемый для преобразования текста
     */
    private final Cipher cipher;

    /**
     * Абстрактный провайдер ключей шифрования
     */
    private final BiFunction<String, String, Key> keyProvider;

    /**
     * Начальный вектор для проведения операции
     */
    public static final byte[] INIT_VECTOR = new byte[16];

    /**
     * Операция симметричного шифрования
     */
    public enum Operation {

        /**
         * Шифрование
         */
        ENCRYPT( Cipher.ENCRYPT_MODE ),

        /**
         * Дешифрование
         */
        DECRYPT( Cipher.DECRYPT_MODE );

        /**
         * Код операции
         */
        private final int code;

        Operation( final int mode ) {
            this.code = mode;
        }

        /**
         * Проведение операции для конкретного шифра
         * Метод обеспечивает синхронизированный доступ к объекту cipher для проведения операции
         */
        public synchronized byte[] perform( final byte[] data, final Cipher cipher, final Key key )
                throws Exception {
            cipher.init( code, key, new IvParameterSpec( INIT_VECTOR ) );
            return cipher.doFinal( data );
        }
    }

    public CryptoService( final BiFunction<String, String, Key> keyProvider ) {
        this.cipher = createCipher();
        this.keyProvider = keyProvider;
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
            final Key secretKey = keyProvider.apply( keyAlias, keyPassword );
            return operation.perform( data, cipher, secretKey );
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
            return Cipher.getInstance( CommonConstants.Algorithms.SYMMETRIC_ALGORITHM_NAME );
        } catch ( Exception exception ) {
            throw new RuntimeException(
                    String.format(
                            CommonConstants.MessageTemplates.ALGORITHM_INIT_ERROR,
                            CommonConstants.Algorithms.SYMMETRIC_ALGORITHM_NAME
                    ),
                    exception
            );
        }
    }
}
