package ru.micromagicman.cryptography.module1;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class App {

    public static final String UNKNOWN_RNG_ALGORITHM_ERROR_MESSAGE =
            "Неизвестный алгоритм генерации псевдослучайных чисел";

    public static final String UNKNOWN_RANDOMIZER_MODE_TYPE_ERROR_MESSAGE_TEMPLATE =
            "Неизвестный тип получения прогноза: %s";

    public static final String SECURE_RNG_ALGORITHM_NAME = "SHA1PRNG";

    private static final String HELP_TEXT_TEMPLATE = """
            Некорректные аргументы командной строки. Ожидается передача двух параметров:
            - Имя пользователя;
            - Способ получения предсказания из списка: %s.

            Пример: java -jar module1-1.0.0-SNAPSHOT.jar Евгений Secure""";

    private static final String RANDOMIZER_MODE_NAMES_DELIMITER = ",";

    private static final String ERROR_MESSAGE_TEMPLATE = "Ошибка: %s\n";

    private static final int PROGRAM_MIN_ARGUMENTS_COUNT = 2;

    /**
     * Варианты предсказаний
     */
    private static final List<String> PREDICTIONS = Arrays.asList(
            "У вас сегодня будет удача в делах!",
            "Сегодня хороший день для саморазвития!"
    );

    public static void main( String[] args ) {
        try {
            if ( args.length < PROGRAM_MIN_ARGUMENTS_COUNT ) {
                throw new IllegalArgumentException(
                        String.format(
                                HELP_TEXT_TEMPLATE,
                                Arrays.stream( RandomizerProvider.values() )
                                        .map( RandomizerProvider::name )
                                        .collect( Collectors.joining( RANDOMIZER_MODE_NAMES_DELIMITER ) )
                        )
                );
            }
            System.out.println( getPrediction( args[0], args[1] ) );
        } catch ( Exception exception ) {
            System.err.printf( ERROR_MESSAGE_TEMPLATE, exception.getMessage() );
        }
    }

    /**
     * Получение предсказания для пользователя
     *
     * @param username       - Имя пользователя
     * @param randomizerMode - Способ получения прогноза
     * @return - Строка-предсказание
     */
    public static String getPrediction( final String username, final String randomizerMode ) {
        final RandomizerProvider randomizerProvider = RandomizerProvider.fromStringName( randomizerMode );
        final MessageService messageService = new MessageService( PREDICTIONS, randomizerProvider );
        return messageService.getPredictionForUser( username );
    }
}
