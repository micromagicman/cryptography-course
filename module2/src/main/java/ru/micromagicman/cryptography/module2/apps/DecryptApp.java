package ru.micromagicman.cryptography.module2.apps;

import ru.micromagicman.cryptography.module2.CommonConstants;
import ru.micromagicman.cryptography.module2.service.CryptoService;
import ru.micromagicman.cryptography.module2.service.DefaultKeyProvider;
import ru.micromagicman.cryptography.module2.service.DigestService;

import java.util.Base64;

import static ru.micromagicman.cryptography.module2.CommonConstants.SYMMETRIC_KEY_ALIAS;

/**
 * Приложение для дешифрации и проверки хэша на валидность
 */
public class DecryptApp {

    public static void main( String[] args ) {
        try {
            if ( args.length < CommonConstants.DECRYPT_APP_MIN_ARGUMENTS_COUNT ) {
                throw new IllegalArgumentException( CommonConstants.MessageTemplates.DECRYPTER_ARGUMENTS_HELP );
            }
            final byte[] cypherText = Base64.getDecoder().decode( args[0] );
            final byte[] plainText = new CryptoService( new DefaultKeyProvider( args[2], args[3] ) )
                    .decrypt( cypherText, SYMMETRIC_KEY_ALIAS, args[4] );
            final String plainTextAsString = new String( plainText );
            System.out.printf( CommonConstants.MessageTemplates.DECRYPT_OUTPUT, plainTextAsString,
                    new DigestService().check( plainTextAsString, args[1] ) );
        } catch ( Exception exception ) {
            System.err.printf( "Произошла ошибка: %s", exception.getMessage() );
        }
    }
}
