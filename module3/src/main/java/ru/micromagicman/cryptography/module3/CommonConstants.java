package ru.micromagicman.cryptography.module3;

/**
 * Общие константы приложения
 */
public final class CommonConstants {

    public static final int ENCRYPT_APP_MIN_ARGUMENTS_COUNT = 5;
    public static final int DECRYPT_APP_MIN_ARGUMENTS_COUNT = 6;
    public static final int ASYMMETRIC_KEY_SIZE = 4096;
    public static final long YEAR_MILLIS = 365 * 24 * 60 * 60 * 1000L;

    /**
     * Наименования алгоритмов
     */
    public static final class Algorithms {
        public static final String KEY_GENERATION = "RSA";
        public static final String ASYMMETRIC_ALGORITHM_NAME = "RSA";
        public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    }

    /**
     * Шаблоны сообщений для форматирования
     */
    public static final class MessageTemplates {
        public static final String ALGORITHM_INIT_ERROR = "Произошла ошибка при инициализации алгоритма %s";
        public static final String OPERATION_ERROR = "Произошла ошибка при совершении операции симметричного шифрования %s";
        public static final String ENCRYPT_OUTPUT = "Зашифрованное сообщение: %s%nПодпись: %s";
        public static final String DECRYPT_OUTPUT = "Дешифрованный текст: %s%n%s%n";
        public static final String ERROR_OUTPUT = "[ОШИБКА]: %s%n";
        public static final String ENCRYPTER_ARGUMENTS_HELP = "Необходимо передать аргументы в следующем формате:" +
                "<шифруемое сообщение> <путь до keystore> <пароль от keystore> <alias ключей в keystore> <пароль для пары ключей шифрования>";
        public static final String DECRYPTER_ARGUMENTS_HELP = "Необходимо передать аргументы в следующем формате:" +
                "<шифртекст> <цифровая подпись> <путь до keystore> <пароль от keystore> <alias ключей в keystore> <пароль для пары ключей шифрования>";
    }
}
