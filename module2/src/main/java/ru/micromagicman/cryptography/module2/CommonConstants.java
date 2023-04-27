package ru.micromagicman.cryptography.module2;

/**
 * Общие константы приложения
 */
public final class CommonConstants {

    public static final int ENCRYPT_APP_MIN_ARGUMENTS_COUNT = 4;
    public static final int DECRYPT_APP_MIN_ARGUMENTS_COUNT = 5;
    public static final int SYMMETRIC_KEY_SIZE = 256;

    public static final String SYMMETRIC_KEY_ALIAS = "MODULE2_HOMEWORK";

    /**
     * Наименования алгоритмов
     */
    public static final class Algorithms {
        public static final String KEY_GENERATION = "AES";
        public static final String DIGEST_ALGORITHM_NAME = "SHA3-512";
        public static final String SYMMETRIC_ALGORITHM_NAME = "AES/CBC/PKCS5Padding";
    }

    /**
     * Шаблоны сообщений для форматирования
     */
    public static final class MessageTemplates {
        public static final String ALGORITHM_INIT_ERROR = "Произошла ошибка при инициализации алгоритма %s";
        public static final String OPERATION_ERROR = "Произошла ошибка при совершении операции симметричного шифрования %s";
        public static final String KEYSTORE_INIT_ERROR = "Произошла ошибка при получении доступа к keystore %s";
        public static final String ENCRYPT_OUTPUT = "Дайджест сообщения: %s%nШифртекст: %s";
        public static final String DECRYPT_OUTPUT = "Дешифрованный текст: %s%nХэш валиден: %s";
        public static final String ERROR_OUTPUT = "Произошла ошибка: %s";
        public static final String ENCRYPTER_ARGUMENTS_HELP = "Необходимо передать аргументы в следующем формате:" +
                "<шифруемое сообщение> <путь до keystore> <пароль от keystore> <пароль от ключа шифрования>";
        public static final String DECRYPTER_ARGUMENTS_HELP = "Необходимо передать аргументы в следующем формате:" +
                "<шифртекст> <хэш для валидации> <путь до keystore> <пароль от keystore> <пароль от ключа шифрования>";
    }
}
