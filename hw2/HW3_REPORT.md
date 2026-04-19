# ОТЧЕТ ПО HW3

Лившиц Леонид Игоревич, БПИ 235, lilivshits@edu.hse.ru

## Используемые данные и конфигурация

На момент основных запусков для скриншотов использовались:

- `INTERFACE_IP=192.168.1.78`
- `INTERFACE_MAC=ac:45:ef:a5:24:f4`
- `GATEWAY_IP=192.168.1.1`
- `ROUTER_MAC=10:50:72:20:b5:c0`
- `DNS_PROVIDER_IP=192.168.1.254`
- `ROOT_DNS_IP=198.41.0.4`

## Запуск приложения

```powershell
cd "C:\Users\tarli\source\repos\CN HW2\CN HW2\hw2"
mvn -q -DskipTests compile
mvn exec:java
```

Команды приложения:

- `help` - показать список команд.
- `dns-capture-start` - включить захват DNS пакетов.
- `dns-capture-stop` - выключить захват DNS пакетов.
- `mx <domain>` - поиск MX и IP почтовых серверов в два шага.
- `compare-root-provider` - сравнение root DNS и DNS провайдера.
- `dns-raw-query <dns-server-ip> <domain> [rr-type]` - отправить raw DNS-запрос через pcap.
- `exit` - выход.

## Выполнение задач

## Задача 1. Захват DNS-пакетов

Запускал `dns-capture-start`, делал тестовый запрос: `dns-raw-query 8.8.8.8 github.com A`, проверял в консоли query/response и совпадение Transaction ID

Скриншоты:

![Задача 1: запуск и перехват](./screenshots/task_1.png)

![Задача 1: детали DNS в приложении](./screenshots/task_1_1.png)

## Задача 2. Поиск IP почтового сервиса через MX (2 шага)

Команда:

```text
mx gmail.com
```

приложение запрашивает mx для домена, получает список хостов (gmail-smtp-in.l.google.com и т.д.), потом для каждого mail-хоста запрашивает A и AAAA

Скриншоты:

![Задача 2: общий результат mx](./screenshots/task_2.png)

![Задача 2: MX-запросы](./screenshots/task_2_mx.png)

![Задача 2: домен почты](./screenshots/task_2_domen.png)

![Задача 2: A-запросы к MX-хостам](./screenshots/task_2_a.png)

![Задача 2: AAAA-запросы к MX-хостам](./screenshots/task_2_aaaa.png)

![Задача 2: ответы DNS в Wireshark](./screenshots/task_2_dns.png)

## Задача 3. Сравнение root DNS и DNS провайдера

Команда:

```text
compare-root-provider
```

Проверяемые домены:

- `github.com`
- `hse.ru`
- `draw.io`

Что делал:

Отправлял запросы к `ROOT_DNS_IP=198.41.0.4`, отправлял те же запросы к `DNS_PROVIDER_IP=192.168.1.254`

по логам:

- Для всех трех доменов пришли валидные ответы с A-записями.
- и root, и provider давали финальные ответы, но с возможными отличиями по TTL/конкретному IP.

### Ответы на вопросы `*`

a) Что выдает в своем ответе корневой сервер?

В моем запуске при запросе к `198.41.0.4` я получил сразу готовые `A`-ответы для `github.com`, `hse.ru`, `draw.io` (IP были в секции `Answer`)

b) Что выдает DNS-сервер провайдера?

DNS провайдера `192.168.1.254` тоже вернул готовые ответы (`RA=true`), в `Answer` сразу были IP-адреса доменов  



Скриншоты:

![Задача 3: общий вывод compare-root-provider](./screenshots/task_3.png)

![Задача 3: фрагмент по github.com](./screenshots/task_3_github.png)

![Задача 3: DNS провайдера и его ответ](./screenshots/task_3_dns_provider_ip.png)

## Что проверял в Wireshark

Использовал фильтры:

- `arp or port 53`
- `dns`
- `ip.addr == 198.41.0.4`
- `ip.addr == 192.168.1.254`
- `dns.qry.type == 15` (MX)
- `dns.qry.type == 1` (A)
- `dns.qry.type == 28` (AAAA)

## Видео

Ссылка на видео находится в на Яндекс Диске
`https://disk.yandex.ru/i/eFYGhiMHak6PiA`

в случае возникновения проблем доступа, напишите мне в тг пожалуйста, `https://t.me/Leo_Livshitz`
