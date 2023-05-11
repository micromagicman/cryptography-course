package ru.micromagicman.cryptography.module3.apps;

import ru.micromagicman.cryptography.module3.CommonConstants;
import ru.micromagicman.cryptography.module3.service.CryptoService;
import ru.micromagicman.cryptography.module3.service.DefaultKeyPairProvider;
import ru.micromagicman.cryptography.module3.service.SignatureService;

import java.security.KeyPair;
import java.util.Base64;
import java.util.function.BiFunction;

/**
 * Приложение для дешифрации и проверки цифровой подписи
 */
public class DecryptApp {

    public static void main( final String[] args ) {
        try {
            if ( args.length < CommonConstants.DECRYPT_APP_MIN_ARGUMENTS_COUNT ) {
                throw new IllegalArgumentException( CommonConstants.MessageTemplates.DECRYPTER_ARGUMENTS_HELP );
            }

            final String cipher = args[0];
            final String signature = args[1];
            final String keyStoreLocation = args[2];
            final String keyStorePassword = args[3];
            final String keyPairAlias = args[4];
            final String keyPairPassword = args[5];

            final BiFunction<String, String, KeyPair> keyPairProvider =
                    new DefaultKeyPairProvider( keyStoreLocation, keyStorePassword );

            final byte[] cypherBytes = Base64.getDecoder().decode( cipher );
            final byte[] plainTextBytes = new CryptoService( keyPairProvider )
                    .decrypt( cypherBytes, keyPairAlias, keyPairPassword );

            final byte[] signatureBytes = Base64.getDecoder().decode( signature );
            final boolean signatureIsOk = new SignatureService( keyPairProvider )
                    .verify( keyPairAlias, keyPairPassword, plainTextBytes, signatureBytes );

            System.out.printf(
                    CommonConstants.MessageTemplates.DECRYPT_OUTPUT,
                    new String( plainTextBytes ),
                    signatureIsOk ? "Signature is OK" : "Signature INCORRECT!"
            );
        } catch ( Exception exception ) {
            System.err.printf( "Произошла ошибка: %s", exception.getMessage() );
        }
    }
}
