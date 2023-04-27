package ru.micromagicman.cryptography.module2.apps;

import ru.micromagicman.cryptography.module2.CommonConstants;
import ru.micromagicman.cryptography.module2.service.CryptoService;
import ru.micromagicman.cryptography.module2.service.DefaultKeyProvider;
import ru.micromagicman.cryptography.module2.service.DigestService;

import java.util.Base64;

import static ru.micromagicman.cryptography.module2.CommonConstants.SYMMETRIC_KEY_ALIAS;

/**
 * Приложение для шифрования текста и хэширования
 */
public class EncryptApp {

    public static void main( String[] args ) {
        try {
            if ( args.length < CommonConstants.ENCRYPT_APP_MIN_ARGUMENTS_COUNT ) {
                throw new IllegalArgumentException( CommonConstants.MessageTemplates.ENCRYPTER_ARGUMENTS_HELP );
            }
            final byte[] cipher = new CryptoService( new DefaultKeyProvider( args[1], args[2] ) )
                    .encrypt( args[0], SYMMETRIC_KEY_ALIAS, args[3] );
            System.out.printf( CommonConstants.MessageTemplates.ENCRYPT_OUTPUT, new DigestService().toHexDigest( args[0] ),
                    Base64.getEncoder().encodeToString( cipher ) );
        } catch ( Exception exception ) {
            System.err.printf( CommonConstants.MessageTemplates.ERROR_OUTPUT, exception.getMessage() );
        }
    }
}
