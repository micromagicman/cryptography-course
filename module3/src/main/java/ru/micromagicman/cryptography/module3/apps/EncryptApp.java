package ru.micromagicman.cryptography.module3.apps;

import ru.micromagicman.cryptography.module3.CommonConstants;
import ru.micromagicman.cryptography.module3.service.CryptoService;
import ru.micromagicman.cryptography.module3.service.DefaultKeyPairProvider;
import ru.micromagicman.cryptography.module3.service.SignatureService;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
import java.util.function.BiFunction;

/**
 * Приложение для шифрования текста и создания цифровой подписи
 */
public class EncryptApp {

    public static void main( final String[] args ) {
        try {
            if ( args.length < CommonConstants.ENCRYPT_APP_MIN_ARGUMENTS_COUNT ) {
                throw new IllegalArgumentException( CommonConstants.MessageTemplates.ENCRYPTER_ARGUMENTS_HELP );
            }

            final String plainText = args[0];
            final String keyStoreLocation = args[1];
            final String keyStorePassword = args[2];
            final String keyPairAlias = args[3];
            final String keyPairPassword = args[4];

            final BiFunction<String, String, KeyPair> keyPairProvider =
                    new DefaultKeyPairProvider( keyStoreLocation, keyStorePassword );

            final byte[] cipher = new CryptoService( keyPairProvider )
                    .encrypt( plainText, keyPairAlias, keyPairPassword );
            final byte[] signature = new SignatureService( keyPairProvider )
                    .create( keyPairAlias, keyPairPassword, plainText.getBytes( StandardCharsets.UTF_8 ) );

            System.out.printf( CommonConstants.MessageTemplates.ENCRYPT_OUTPUT, Base64.getEncoder().encodeToString( cipher ),
                    Base64.getEncoder().encodeToString( signature ) );
        } catch ( Exception exception ) {
            System.err.printf( CommonConstants.MessageTemplates.ERROR_OUTPUT, exception.getMessage() );
        }
    }
}
