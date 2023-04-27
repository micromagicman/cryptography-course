package ru.micromagicman.cryptography.module2.service;

import ru.micromagicman.cryptography.module2.CommonConstants;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Сервис создания дайджеста (хэша) сообщения
 */
public class DigestService {

    /**
     * Алгоритм хэширования
     */
    private final MessageDigest digest;

    public DigestService() {
        this.digest = createDigest();
    }

    /**
     * Проверка соответствия переданного текста хэшу
     */
    public boolean check( final String plainText, final String hexDigest ) {
        return Objects.equals( hexDigest, toHexDigest( plainText ) );
    }

    /**
     * Получение дайджеста сообщения в виде строки в шестнадцатеричном формате
     */
    public String toHexDigest( final String plainText ) {
        byte[] result;
        synchronized ( this ) {
            digest.update( plainText.getBytes( StandardCharsets.UTF_8 ) );
            result = digest.digest();
            digest.reset();
        }
        return byteArrayToHex( result );
    }

    /**
     * Инициализация алгоритма хэширования
     */
    private MessageDigest createDigest() {
        try {
            return MessageDigest.getInstance( CommonConstants.Algorithms.DIGEST_ALGORITHM_NAME );
        } catch ( NoSuchAlgorithmException exception ) {
            throw new RuntimeException(
                    String.format(
                            CommonConstants.MessageTemplates.ALGORITHM_INIT_ERROR,
                            CommonConstants.Algorithms.DIGEST_ALGORITHM_NAME
                    ),
                    exception
            );
        }
    }

    /**
     * Преобразование массива байт в шестнадцатеричную строку
     */
    private String byteArrayToHex( byte[] data ) {
        final StringBuilder stringBuilder = new StringBuilder( data.length << 1 );
        for ( byte byteElement : data ) {
            stringBuilder.append( String.format( "%02x", byteElement ) );
        }
        return stringBuilder.toString();
    }
}
