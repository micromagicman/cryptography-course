# Домашнее задание №3

Напишите консольное приложение, которое будет алгоритмом "RSA" зашифровывать строку "Java" и генерировать для зашифрованной строки цифровую подпись алгоритмом "SHA256withRSA". Пару ключей нужно тоже сгенерировать алгоритмом "RSA".

## Задание на 5+:

Напишите второе консольное приложение, которое будет использовать туже пару ключей для расшифровки строки и проверки подписи. Расшифрованное значение нужно вывести на консоль и если подпись корректная, то вывести "Sign is ok".

## Запуск приложений

### Шифрование

```bash
java -cp build/libs/module3-1.0.0-SNAPSHOT.jar ru.micromagicman.cryptography.module3.apps.EncryptApp Java keystore keystorePassword module3 keyPassword
```

### Дешифрование
```bash
java -cp build/libs/module3-1.0.0-SNAPSHOT.jar ru.micromagicman.cryptography.module3.apps.DecryptApp ZdYDD6vRMK4pE9alNKFro43pudT09JnvBv/85SR3NQovrPlG/bfeJDgeKcZ4Xr/6RhXYuIvWRWx87Ss262qH2fW7oThBxvMaCYWXb7PFr2sFhuUl4yD+kKm4KiKPA6HDGLyEwRcLJOWL5nz2OByv0W7Yj257FcLTTxz3BATRSRxcPNapg56fRdvEkkeQ8/cFPVUVYky20sl6LEgeKxMjdfN39MDoITs0ntWJHweVgQaJFKZI2e5BPM51MsdwK79u7zF91eablePNDgjfZ290SK2jyPPraTKho1sCBHC9p6LjIPYSCU9PPjyAr/RksWXdffSg8XvfZGgPUuoFONy0gKEh2x06YizejbZI4dW3nV+r+NTpYffr+hAmaU3G1DHdzlRwNqZBZezYq+jwZJtIBwd2lACOzqPXP4H4XrKs1EDkCEbJg44oSlAyL7UwAGYtrGbpdmcI0NWQpgZWW4/mx4cgR9S+o/j4U5GvEb5vuP5mxcWxZIEGpeBwCUUY0xOdbstM+FHq+nrp+oTjjxynbLZYwOP5soQ2ruPm6suddXvGfkCo+AtQvnJ4anygQ8YBcZNsNQUfx5kwu8XBRTZ7lEl9XJxw1m3kU78dviYW55Do/OJbEN1rEI2tG3nXnj6/TpXdN9iFx37di7Y9BBvImwRBA3kA8HRayofBiF3Kcd0= iGG8xaYZKQVAJK/5swU80qF5tXzHS+k6ETuYwVtlat3cUSlufJfeUpaHpQVKbM0dkbVC6t3hm4iGjUsApzlWwUOoomYZFFgScldLuP2aj8nR9rFBlhw2maQoVhqXsHGfP7IjyIfez/h1Zy+akC2Oth5/OYbHkx+bFi2qlpIFAZYcm0nHXPKoqAyp0ZOsem9elXYZsXfqTQcUd1khHojq9hwgzxtD66NqL9TLjrIXQlCUXBuulLBnrbrYCH0+0yR8nTD/aiM3Kfj6KZl1oTlVoQVTy1pkJMstLFZml/hMvfcMaN0lkmZSykTn1LaaazaNZJMycClC+vCp4GUznMgf6akZc1LVZRA3aw+VEm4cCA9HdLNpGkK6Lg9hsvi/oJoPwIPJSO7+0wH6q+jCGma7cv9S6mexuMdMlJiQhd9OA94f7TMlDSub4aZxH/W86ZMsrgAAE1x6V555yi1H7PaIjxNbb3r66Ue6XSlV+TI7PQakhTc3IOvhobZnHJHgywABXUuGCciAuRdTEEZ59f84aUhmTxJGUsXd/pZf5s5gZZ7uB2ourBnqAQ4NAn/8v6u/cC4q4r49jeR1YSbbcBu2075Hc54jIh28w3IYgiCtGg/DaTHclIgVlPKaGkVa9EKHEQHjKvatKMQV+fiGeZX7hgoG9le2NpO+AJADgxq/T3M= keystore keystorePassword module3 keyPassword
```