# Домашнее задание №2

Напишите консольное приложение для шифрования "секретного слова". Приложение получает его в качестве первого параметра. После получения секретного слова приложение:

- вычисляет для него хеш сумму;
- зашифровывает его алгоритмом "AES/CBC/PKCS5Padding".

На консоль выводится 2 значения: хеш секретного слова и зашифрованное слово алгоритмом "AES/CBC/PKCS5Padding".

## Задание на 5+:

Напишите приложение для расшифровки и проверки хеш суммы.

## Запуск приложений

### Шифрование

```bash
java -cp build/libs/module2-1.0.0-SNAPSHOT.jar ru.micromagicman.cryptography.module2.apps.EncryptApp Евгений keystore password keyPassword
```

### Дешифрование
```bash
java -cp build/libs/module2-1.0.0-SNAPSHOT.jar ru.micromagicman.cryptography.module2.apps.DecryptApp uCTls00ljZLjj444yzi8WA== 4bded496e0b3f052404f
19370be9687df326e55ed4ecda8a72a87b92238098d7f0b9690288f317a01098a6a4b87b5bec46b3570b6248d70404d31c684c1a6042 keystore password keyPassword
```