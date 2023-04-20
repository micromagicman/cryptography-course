package ru.micromagicman.cryptography.module1;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.Random;
import java.util.function.Function;

public enum RandomizerProvider {

    /**
     * Базовый способ получения последовательности псевдослучайных чисел
     * Основан на классе {@link java.util.Random}
     */
    BASIC( Random::new ),

    /**
     * "Безопасный" способ получения последовательности псевдослучайных чисел
     * Основан на классе {@link java.security.SecureRandom} и RNG-алгоритме SHA1PRNG
     */
    SECURE( RandomizerProvider::getSecureRandom );

    /**
     * Функция, получающая на вход seed в виде long
     * и возвращающая одну из реализаций генератора псевдослучайных чисед
     */
    private final Function<Long, ? extends Random> randomProvider;

    RandomizerProvider( final Function<Long, ? extends Random> randomProvider ) {
        this.randomProvider = randomProvider;
    }

    /**
     * Получение провайдера RNG
     * @param name - Имя провайдера
     * @return - Провайдер, если он доступен для заданного имени
     *
     * @throws IllegalArgumentException - в случае остутствия провайдера по заданному имени
     */
    public static RandomizerProvider fromStringName( final String name ) {
        final String nameUpperCase = name.toUpperCase();
        return Arrays.stream( values() )
                .filter( rp -> Objects.equals( rp.name(), nameUpperCase ) )
                .findFirst()
                .orElseThrow( () ->
                        new IllegalArgumentException( String.format(
                                App.UNKNOWN_RANDOMIZER_MODE_TYPE_ERROR_MESSAGE_TEMPLATE,
                                name
                        ) )
                );
    }

    /**
     * Создание объекта RNG
     * @param seed - Начальный seed для RNG
     * @return - Одна из реализаций RNG
     */
    public Random getRandomizer( final long seed ) {
        return randomProvider.apply( seed );
    }

    private static Random getSecureRandom( final long seed ) {
        try {
            final Random randomizer = SecureRandom.getInstance( App.SECURE_RNG_ALGORITHM_NAME );
            randomizer.setSeed( seed );
            return randomizer;
        } catch ( NoSuchAlgorithmException exception ) {
            throw new IllegalArgumentException( App.UNKNOWN_RNG_ALGORITHM_ERROR_MESSAGE, exception );
        }
    }
}
