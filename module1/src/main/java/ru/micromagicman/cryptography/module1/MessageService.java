package ru.micromagicman.cryptography.module1;

import java.util.List;
import java.util.Random;

public class MessageService {

    private static final String GREETING_TEMPLATE = "%s, %s";

    private static final String EMPTY_LIST_ERROR_MESSAGE = "Список сообщений пуст!";

    /**
     * Генератор последовательности псевдослучайных чисел
     */
    private final Random randomizer;

    /**
     * Шаблоны сообщений с предсказаниями
     */
    private final List<String> messageTemplates;

    public MessageService(
            final List<String> messageTemplates,
            final RandomizerProvider randomizerProvider ) {
        if ( messageTemplates.isEmpty() ) {
            throw new IllegalArgumentException( EMPTY_LIST_ERROR_MESSAGE );
        }
        this.messageTemplates = messageTemplates;
        this.randomizer = initRandomizer( messageTemplates, randomizerProvider );
    }

    /**
     * Получение предсказания для пользователя
     *
     * @param username - Имя пользователя
     * @return - Строка-предсказание
     */
    public String getPredictionForUser( final String username ) {
        return String.format( GREETING_TEMPLATE, username, randomizePrediction() );
    }

    /**
     * Выбор случайного предсказания из доступных
     */
    private String randomizePrediction() {
        return messageTemplates.get( randomizer.nextInt( messageTemplates.size() ) );
    }

    /**
     * Инициализация одной из реализаций RNG
     */
    private Random initRandomizer(
            final List<String> messageTemplates,
            final RandomizerProvider randomizerProvider ) {
        final long seed = System.nanoTime() ^ ( randomizerProvider.hashCode() * 31L + messageTemplates.hashCode() );
        return randomizerProvider.getRandomizer( seed );
    }
}
