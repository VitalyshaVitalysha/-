DNSCRYPT: КАК ЗАШИФРОВАТЬ ТРАФИК DNS В UBUNTU ИЛИ LINUX MINT 
(обезопасить адрес от утечек) и получить широкий доступ к серверам.

DNSCrypt - это протокол для обеспечения безопасности обмена данными между клиентом и распознавателем DNS, предотвращающий шпионские, спуфинговые или посреднические атаки . Чтобы использовать его, вам понадобится инструмент под названием dnscrypt-proxy , который « можно использовать непосредственно в качестве локального распознавателя или пересылки DNS, аутентифицировать запросы с использованием протокола DNSCrypt и передавать их на вышестоящий сервер ». Наиболее популярной клиентской реализацией DNSCrypt является dnscrypt-proxy . Он может использоваться самостоятельно или через один из графических пользовательских интерфейсов.

Помимо реализации протокола, dnscrypt-proxy может быть расширен с помощью плагинов и дает большой контроль над локальным трафиком DNS:

Просматривайте DNS-трафик, исходящий из вашей сети, в режиме реального времени и обнаруживайте скомпрометированные хосты и приложения, звонящие домой.
Локально блокируйте рекламу, трекеры, вредоносные программы, спам и любой веб-сайт, чьи доменные имена или IP-адреса соответствуют определенным вами правилам.
Предотвратить утечку запросов для локальных зон.
Уменьшите задержку за счет кэширования.
Принудительно использовать трафик TCP для маршрутизации через туннели только TCP или Tor.

Требования:
Cистема с Windows 7 SP1 . NET Framework 4.6.1 .
Вам также понадобится: Microsoft Visual C ++ распространяемый для Visual Studio 2017 x64 или x86
Установка
Эксешник кидаете через настройки интерфейса и приложений Вайн, а установщик через деинсталлятор.
Для установки Simple DNSCrypt используйте самые последние (стабильные) пакеты MSI: x86 или x64 .
Порядок установки фреймворка не имеет значения, укажите требуемый и он подхватит всё остальное. При установке будет много ошибок, как обычно - отвечайте утвердительно.
 
LINUX
Здесь я предлагаю минимальные настройки и результат с отключенным Тor,в архиве файл toml содержит эти настройки,вы можете взять его или добавить (расскоментировать строки) самостоятельно.Тоr не мешает, но тянет одеяло udp на себя, 
поэтому крипт переключен в режим tcp чего Tor не умеет. Пакет Tor это сервис, можно попробовать исключить автозагрузку так
update-rc.d -f tor remove но это не эффективно и хуже чем отключать его  sudo service tor stop
запустить при необходимости так: sudo service tor restart 
либо удалите его совсем, заведите портабл, и пользуйтесь Vpn плагинами, часто вам нужен Onion ? )
Разница в скорости DNS кэша между ними большая (однако сам я просто выключаю его,ибо портабл это разъёб диска,а Tor ещё и Телега ).

sudo apt purge dnscrypt-proxy unbound и принять настройки следующего пакета ...
Ставим:
sudo add-apt-repository ppa:shevchuk/dnscrypt-proxy
Либо сурс: https://github.com/jedisct1/dnscrypt-proxy/releases/latest
sudo apt-get update && sudo apt-get install -y haveged 
sudo dpkg -i dnscrypt-proxy_2.0.23_ppa1_bionic_i386.deb

Cинхронизируйте часы:
sudo systemctl start systemd-timesyncd

Оболочка для винды: 

https://www.simplednscrypt.org/

Главный сайт:

https://www.dnscrypt.org/#dnscrypt-proxy

Оболочка графического интерфейса Qt / KF5 через dnscrypt-proxy (v.1 и v.2)

https://github.com/F1ash/dnscrypt-proxy-gui

Содержит экземпляр модуля systemd для управления прокси-сервером. Работает с локальным (по умолчанию 127.0.0.1) адресом и списком услуг из пакета dnscrypt-proxy. Реализовано восстановление системных настроек DNS resolver. 

Далее:

sudo service tor stop
sudo -s

Если сокет занят узнайте не тор ли это
ss -lp 'sport = :domain'
он может быть виден как 
127.0.0.1:53
Гляньте на интерфейсы
ip a
Если у вас была нерабочая конфигурация, то сейчас она должна работать, а 
следующие настройки описывают схему старого пакета и вам ничего из ниже описанного не нужно делать,более того это сломает свежую,все представленные каталоги старой версии становятся пусты,кроме sudo systemctl edit dnscrypt-proxy.socket --full  , тем не менее если свежая не работает, или наебнётся потом, то вам прийдётся добавить например резолверы sudo nano /usr/share/dnscrypt-proxy/dnscrypt-resolvers.csv хотя новый пакет читает без него и альтернативу в sudo nano /usr/local/etc/dnscrypt-proxy.conf ...
Когда вы откроете toml нового пакета многое будет закомментировано и мой вам совет - добавляйте строчки которые вм нужны, а не 
удаляйте коммент заглушку, таким образом вы всегда будете иметь изначальный конфиг если что то наварзаете,либо продублируйте этот файл в той же директории но с префиксом 1 или 2 тем самым потом удалите поломанный и восстановите прежний удалив префикс:

То что я изменил по существу:

sudo nano /etc/dnscrypt-proxy/dnscrypt-proxy.toml

# server_names = ['scaleway-fr', 'google', 'yandex', 'cloudflare']
server_names = ['scaleway-fr']
ещё в пунктах:
fallback_resolver = '8.8.8.8:53'
force_tcp = true
ignore_system_dns = true

Меняем файл резолвинга на свой:

sudo rm /etc/resolv.conf
sudo service network-manager restart

sudo nano /etc/resolv.conf

nameserver 127.0.0.1
nameserver 127.0.2.1

Установка запрета на его перезаписьслужбами - $ sudo chattr +i /etc/resolv.conf
Снятие запрета - $ sudo chattr -i /etc/resolv.conf

В минт все сессии гостевые, если они не запрещены параметрами входа, после запрета есть возможность выбора
и создания подобных запретов.

Далее:
sudo nano /usr/local/etc/dnscrypt-proxy.conf 

## Ручные настройки, только для пользовательского распознавателя, отсутствующего в файле CSV
ProviderName 2.dnscrypt.resolver.example
ProviderKey E801: B84E: A606: BFB0: BAC0: CE43: 445B: B15E: BA64: B02F: A3C4: AA31: AE10: 636A: 0790: 324D
ResolverAddress 203.0.113.1:443  

Вот так выглядит проверка и работа свежего пакета с toml файлом, что ниже ...

ss -lprtus

Total: 969
TCP:   12 (estab 2, closed 0, orphaned 0, timewait 0)

Transport Total     IP        IPv6
RAW	  1         1         0        
UDP	  12        7         5        
TCP	  12        7         5        
INET	  25        15        10       
FRAG	  0         0         0        

Netid   State     Recv-Q    Send-Q                              Local Address:Port           Peer Address:Port    
udp     UNCONN    23232     0                                       127.0.2.1:domain              0.0.0.0:*       
udp     UNCONN    0         0                                         0.0.0.0:ipp                 0.0.0.0:*       
udp     UNCONN    22464     0                                     ваш ip     :ntp                 0.0.0.0:*       
udp     UNCONN    0         0                                       localhost:ntp                 0.0.0.0:*       
udp     UNCONN    0         0                                         0.0.0.0:ntp                 0.0.0.0:*       
udp     UNCONN    0         0                                         0.0.0.0:50833               0.0.0.0:*       
udp     UNCONN    14784     0                                         0.0.0.0:mdns                0.0.0.0:*       
udp     UNCONN    0         0                         [мак адрес]     %enp1s0:ntp                    [::]:*       
udp     UNCONN    0         0                                   ip6-localhost:ntp                    [::]:*       
udp     UNCONN    0         0                                            [::]:ntp                    [::]:*       
udp     UNCONN    21696     0                                            [::]:mdns                   [::]:*       
udp     UNCONN    0         0                                            [::]:37189                  [::]:*       
tcp     LISTEN    0         128                                       0.0.0.0:http                0.0.0.0:*       
tcp     LISTEN    0         128                                     127.0.2.1:domain              0.0.0.0:*       
tcp     LISTEN    0         128                                       0.0.0.0:ssh                 0.0.0.0:*       
tcp     LISTEN    0         5                                       localhost:ipp                 0.0.0.0:*       
tcp     LISTEN    0         100                                       0.0.0.0:smtp                0.0.0.0:*       
tcp     LISTEN    0         128                                          [::]:http                   [::]:*       
tcp     LISTEN    0         128                                          [::]:ssh                    [::]:*       
tcp     LISTEN    0         5                                   ip6-localhost:ipp                    [::]:*       
tcp     LISTEN    0         100                                          [::]:smtp                   [::]:*       
tcp     LISTEN    0         128                                             *:9094                      *:* 

ss -lp 'sport = :domain'
Netid      State        Recv-Q       Send-Q              Local Address:Port               Peer Address:Port       
udp        UNCONN       27456        0                       127.0.2.1:domain                  0.0.0.0:*          
tcp        LISTEN       0            128                     127.0.2.1:domain                  0.0.0.0:*  

СТАТУС СОКЕТОВ DNS

sudo systemctl status dnscrypt-proxy.socket
● dnscrypt-proxy.socket - dnscrypt-proxy listening socket
   Loaded: loaded (/etc/systemd/system/dnscrypt-proxy.socket; enabled; vendor preset: enabled)
   Active: active (running) since Sat 2019-05-11 18:17:09 MSK; 42min ago
     Docs: man:dnscrypt-proxy(8)
   Listen: 127.0.2.1:53 (Stream)
           127.0.2.1:53 (Datagram)
    Tasks: 0 (limit: 2261)
   CGroup: /system.slice/dnscrypt-proxy.socket

Будут проблемы посмотрите соответствие сокетов:

sudo systemctl edit dnscrypt-proxy.socket --full
[Unit]
Description=dnscrypt-proxy listening socket
Documentation=man:dnscrypt-proxy(8)
Wants=dnscrypt-proxy-resolvconf.service

[Socket]
ListenStream=127.0.2.1:53
ListenDatagram=127.0.2.1:53

[Install]
WantedBy=sockets.target

СТАТУС DNS-proxy

systemctl status dnscrypt-proxy.service
● dnscrypt-proxy.service - DNSCrypt-proxy client
   Loaded: loaded (/lib/systemd/system/dnscrypt-proxy.service; enabled; vendor preset: enabled)
   Active: active (running) since Sat 2019-05-11 18:41:46 MSK; 19min ago
     Docs: https://github.com/jedisct1/dnscrypt-proxy/wiki
 Main PID: 26787 (dnscrypt-proxy)
    Tasks: 7 (limit: 2261)
   CGroup: /system.slice/dnscrypt-proxy.service
           └─26787 /usr/bin/dnscrypt-proxy --config /etc/dnscrypt-proxy/dnscrypt-proxy.toml

мая 11 18:41:46 ll systemd[1]: Started DNSCrypt-proxy client.
мая 11 18:41:47 ll dnscrypt-proxy[26787]: [2019-05-11 18:41:47] [WARNING] /etc/dnscrypt-proxy/public-resolvers.md:
мая 11 18:41:47 ll dnscrypt-proxy[26787]: [2019-05-11 18:41:47] [WARNING] /etc/dnscrypt-proxy/public-resolvers.md.
мая 11 18:41:47 ll dnscrypt-proxy[26787]: [2019-05-11 18:41:47] [NOTICE] Source [public-resolvers.md] loaded
мая 11 18:41:47 ll dnscrypt-proxy[26787]: [2019-05-11 18:41:47] [NOTICE] dnscrypt-proxy 2.0.23
мая 11 18:41:47 ll dnscrypt-proxy[26787]: [2019-05-11 18:41:47] [NOTICE] Wiring systemd TCP socket #0, dnscrypt-pr
мая 11 18:41:47 ll dnscrypt-proxy[26787]: [2019-05-11 18:41:47] [NOTICE] Wiring systemd UDP socket #1, dnscrypt-pr
мая 11 18:41:47 ll dnscrypt-proxy[26787]: [2019-05-11 18:41:47] [NOTICE] [yandex] OK (DNSCrypt) - rtt: 34ms
мая 11 18:41:47 ll dnscrypt-proxy[26787]: [2019-05-11 18:41:47] [NOTICE] Server with the lowest initial latency: y
мая 11 18:41:47 ll dnscrypt-proxy[26787]: [2019-05-11 18:41:47] [NOTICE] dnscrypt-proxy is ready - live servers: 1  


Сделайте себе кнопки в deepin-terminal или подобный
sudo service network-manager restart
sudo service tor stop
sudo service tor restart
sudo systemctl stop dnscrypt-proxy
sudo systemctl start dnscrypt-proxy
systemctl status dnscrypt-proxy.service
sudo nano /etc/dnscrypt-proxy/dnscrypt-proxy.toml

Я рекомендую простую конфигурацию через pppoeconf,однако мне не удалось его добавить в автозагрузку и я поднимаю его в ручную, а подключение через Nmanager имеет смысл только при статичном адресе, со своей внутренней сетью устройств и 
скорее всего потребуется вот это - блокировщик нежелательных хостов,по странам и блэк листам:

NoTrack Панель администрирования DNS http://имярек/admin/

Install NoTrack

wget https://gitlab.com/quidsup/notrack/raw/master/install..
bash install.sh

Uninstall NoTrack
sudo bash /opt/notrack/uninstall.sh
or sudo bash ~/notrack/uninstall.sh

Предупреждение: Dnsmasq не удалось перезапустить. Это может быть связано с конфликтом с разрешенной службой systemd, выполняющей DNS-сервер заглушки на порту 53.
Эта проблема, как известно, влияет на Ubuntu 19.04

Я могу исправить проблему, добавив DNS Stub Listener=no в /etc/systemd / resolved.конф
Вы хотите, чтобы я изменить решены.conf (Y / n)?

https://github.com/quidsup/notrack
https://gitlab.com/quidsup/notrack

NM всегда будет пытаться смотреть в сеть через LAN dhcp-локалку,а NoTrack установит веб панель и dnsmasq,
ни в том ни в другом нет необходимости при DSL (динамических адресах)...
Обратите внимание на файл: sudo nano /etc/systemd/resolved.conf


КОНЕЦ )

№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№

СТАРЫЕ НАСТРОЙКИ ...

Откройте sudo nano /etc/dnscrypt-proxy/dnscrypt-proxy.conf и поместите:

# A more comprehensive example config can be found in
# /usr/share/doc/dnscrypt-proxy/examples/dnscrypt-proxy.conf

ResolverName  fvz-any #(или cisco)
Daemonize yes

# LocalAddress only applies to users of the init script. systemd users must
# change the dnscrypt-proxy.socket file.
LocalAddress 127.0.0.1:53
LocalAddress 127.0.1.2:53
LocalAddress 127.0.2.1:53
LocalAddress 127.0.2.2:53

ИНТЕРФЕЙС

https://github.com/F1ash/dnscrypt-proxy-gui

sudo apt-get install -y extra-cmake-modules qtbase5-dev libkf5auth-dev libkf5notifications-dev qtbase5-private-dev
sudo cmake ./
sudo make install
sudo -s
DNSCryptClient

Интерфейс может не сработать он для федоры...

Используемые сервера прописаны здесь:
sudo nano /usr/share/dnscrypt-proxy/dnscrypt-resolvers.csv

Статус схемы может говорить о маске:
systemd-resolve --status
Решается это так:
sudo systemctl list-unit-files
sudo systemctl unmask systemd-resolved.service

Если активности нет, решайте что вам делать по этой инструкции но это очень старая конфигурация...
https://github.com/jedisct1/dnscrypt-proxy/wiki/Installation-linux
Поэтому говорю сразу - Тор вцелом программе не помеха, конфликтов нет ! Службы, резолверы, сервис слушают разные протоколы,а соединение и кастомная настройка network-manager c dns у каждого разные, курите что вам лучше, всё работает и через pppoeconf и NM ...

Учтите есть резолверы с блоками,например:
adguard-dns-family-ns2, «Adguard DNS Family Protection 2», «Adguard DNS с безопасным поиском и блокировкой контента для взрослых», «Anycast», «», https: //adguard.com/en/adguard-dns/overview. HTML, 1, нет, да, нет, 176.103.130.134: 5443,2.dnscrypt.family.ns2.adguard.com, 8C21: 17A9: EBC1: 57D6: FB64: 056F: 0ADB: C11C: 5D83: 6734: 73С4: 6E25: 8D9B: 2F57: D4EE: 351F, pk.family.ns2.adguard.com

Связанные вопросы:
https://www.linux.org.ru/tag/dnscrypt?section=2
Кстати работоспосоность сервака просто проверить спастив его в браузер  ...

Всё это устанавливается упрощённо в качестве поддержки, при Ч/п я думаю сослужит хорошую службу.

https://github.com/dyne/dnscrypt-proxy/blob/master/dnscrypt-proxy.conf
https://www.linuxuprising.com/2018/10/install-and-enable-dnscrypt-proxy-2-in.html

Протестируйте утечку по ссылке ниже - не доверяйте тесту OpenDNS, он себя скомпроментировал ...
https://dnsleaktest.com/
Вы должны увидеть адрес своего провайдера и больше ничего!
Это говорит о том, что вы способны на многое,но даже провайдер не подозревает о ваших возможностях.
Если вы используете Tor или VPN то и соответственно тест покажен иные результаты но вашего провайдера там быть не должно, если только он не входит в эти структуры!)


Для OpenVPN вы можете предотвратить утечки DNS, указав новую опцию . Просто откройте файл .conf для сервера, к которому вы подключаетесь (sudo nano /etc/openvpn/например sergiy-pc.ovpn ) , и добавьте следующее в новой строке: block-outside-dns . Для получения дополнительной информации см. Руководство OpenVPN. 

https://losst.ru/prostaya-nastrojka-openvpn-linux


ПОЯСНЯЮ ЗА КАСТОМ)

dig yandex.ru +nssearch
При исправном соединении это должен быть запрос не более (2 мсек).

https://blog.foxylab.com/shifruem-dns-zaprosy-ili-dnscrypt-proxy-v-dejstvii/

Сохраните копию исходного файла конфигурации example-dnscrypt-proxy.toml и настройте согласно вашим требованиям как dnscrypt-proxy.toml.(тоесть уберите имя example) Где его взять ? Он ниже ...

Сохраняем здесь:
sudo nano /etc/dnscrypt-proxy/dnscrypt-proxy.toml

Пример файла конфигурации с удаленными комментариями,её и сохраняете:

server_names = ['yandex']
listen_addresses = ['127.0.0.1:53', '127.0.2.1:53' '[::1]:53']
max_clients = 250
#user_name = 'nobody'
ipv4_servers = true
ipv6_servers = true
dnscrypt_servers = true
doh_servers = true
require_dnssec = false
require_nolog = true
require_nofilter = true
disabled_server_names = []
force_tcp = true
proxy = "socks5: //127.0.0.1: 9050"
http_proxy = "http://127.0.0.1:8888"
timeout = 2500
keepalive = 60
refused_code_in_responses = false
lb_strategy = 'p2'
log_level = 0
log_file = 'dnscrypt-proxy.log'
use_syslog = false
cert_refresh_delay = 240
dnscrypt_ephemeral_keys = false
tls_disable_session_tickets = true
#49199 = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
#49195 = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
#52392 = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
#52393 = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
tls_cipher_suite = []
fallback_resolver = '8.8.8.8:53'
ignore_system_dns = true
netprobe_timeout = 30
offline_mode = false
log_files_max_size = 1
log_files_max_age = 1
log_files_max_backups = 1
block_ipv6 = false
forwarding_rules = 'forwarding-rules.txt'
cloaking_rules = 'cloaking-rules.txt'
cache = true
cache_size = 512
cache_min_ttl = 600
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600
[Query_log]
file = 'query.log'
format = 'tsv'
ignored_qtypes = ['DNSKEY', 'NS']
[Nx_log]
file = 'nx.log'
format = 'tsv'
[blacklist]
blacklist_file = 'blacklist.txt'
[Ip_blacklist]
blacklist_file = 'ip-blacklist.txt'
[wite list]
whitelist_file = 'whitelist.txt'
[schedules]
# [schedules.'time-to-sleep ']
# mon = [{after = '21: 00 ', before =' 7: 00 '}]
# вт = [{после = '21:00', до = '7:00'}]
# wed = [{after = '21: 00 ', before =' 7: 00 '}]
# thu = [{after = '21: 00 ', before =' 7: 00 '}]
# fri = [{after = '23: 00 ', before =' 7: 00 '}]
# sat = [{after = '23: 00 ', before =' 7: 00 '}]
# sun = [{after = '21: 00', before = '7: 00'}]

# [schedules.'work ']
# mon = [{after = '9: 00', before = '18: 00 '}]
# вт = [{после = '9: 00', до = '18: 00 '}]
# wed = [{after = '9: 00', before = '18: 00 '}]
# thu = [{after = '9: 00', before = '18: 00 '}]
# fri = [{after = '9: 00', before = '17: 00 '}]
[sources]
[sources.'public-resolvers', 'yandex', 'onion-services']
urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/public-resolvers.md', 'https://download.dnscr$']
minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
cache_file = 'public-resolvers.md'
refresh_delay = 240
prefix = ''
[static.'google']
stamp = 'sdns: // AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA'

############################################################################################################################

DNS-резольвер (имя в скобках) принимает запрос от клиента (Вашего компьютера) и отправляет его к DNS-серверу.
Эти резольверы описаны в файле public-resolvers.md.

Пример описания DNS-резольвера:

## aaflalo-me
DNS-over-HTTPS server running rust-doh with PiHole for Adblocking.
Non-logging, AD-filtering, supports DNSSEC.
Hosted in Netherlands on a RamNode VPS.
sdns: //AgMAAAAAAAAADjE3Ni41Ni4yMzYuMTc1ID4aGg9sU_PpekktVwhLW5gHBZ7gV6sVBYdv2D_aPbg4DmRucy5hYWZsYWxvLm1lCi9kbnMtcXVlcnk

# aaflalo-me - имя резольвера, которое и подставляется в файл конфигурации вместо зведочек.

Будьте внимательны к имени в пунктах sоurces и servers,у публичных ключи одинаковы и нужно просто вписать имя конкретного сервера в начале конфига, таким образом добавляя приватный вы скорее всего уберёте или закоммите сурсы публичных. Приватный ключ можно добавить не убирая общественный из конфига,всё зависит от имени сервера.Если это сборка,с именем 'public-resolvers',то автоматом выбирается самый быстрый.В общем не меняйте ничего в предложенном, он работает более чем. Специфические приватные чаще имеют блэк-лист, но его можно скачать отдельно. В общем думайте сами )
Состояние должно быть активным и показывать имя сервера,его так же можно увидеть на сайте теста ...

Самыми важными свойствами резольвера являются:

Non-logging — не ведет протокол запросов
supports DNSSEC — поддерживает цифровую подпись — DNSSEC
AD-filtering — фильтрует рекламные запросы
Также в файле конфигурации задан локальный адрес для прием DNS-запросов (выделен синим цветом):
127.0.0.1:53

За всей инфой можно зайти сюды:
https://dnscrypt.info/public-servers
А это репо со всем необходимым:
https://download.dnscrypt.info/

Если активен Тор, то вы не добъётесь чистоты эксперимента ...

Общедоступные серверы - резолверы:
https://download.dnscrypt.info/resolvers-list/v2/public-resolvers.md

№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№

BENCHMARK

Now ranking the performance of 4,849 resolvers for the creation of your

Так, все пиздюляторы заправить пиздюляторством, стартуем !
Заметьте, что DNS это в основном преобразование имени yandex.ru в ip cервера,а в случае с dnscrypt-proxy я могу указать просто имя и он должен его найти хоть из под земли,но только если сайт лайтовый, а не помойка ( для верхних авторитарных доменов). 
Затем я пробую сокет Tor (cам Тор отключен) через приложение браузера, пытаясь подключиться к Rutracker.org и при любом варианте, я не вижу заглушки, но подобные сайты мне не доступны, обходом через тунелирование запроса. Ставлю Hola и всё работает, но заменой Tor в системе не является - Onion cайты, как и i2p таким образом не доступны.
Можно ли использовать Tor вместе с dnscrypt-proxy - lf ) Я серьёзных конфликтов не замечал. Пробую медиацентр - всё работает, как и раньше.
Подключаю Benchmark и задаю создание кастомного листа, после проверки им моей коммуникации (он сам предложит). Не нужно ничего вырезать и трогать ... Через пол часа получаю в принципе то, что сам бы сделал ручками, но куда это девать в любом случае ? Х.з файл сохраняется под именем ini можно открывать его в бенче, читать имена и пробовать вставлять их в dns-proxy, но это целая история с ключами и прочей маятой. Меняет ли он что то на уровне системы, я думаю нет, всё таки это приблуда для сис.админов серверов, вот они могут себе позволить многое. Проверяю очищенный файл, экспортирую результат в csv , ну вот в общем и всё )
В общем то конфигурация dnscrypt весьма гибкая, главное решить какие параметры вам необходимы и всё это описывается в 15 строк.
Уберите или добавьте правила блокировки, подберите соответствующий сервер, фри или с цензурой и т.д ...
Зайдите на https://ipleak.net/ теперь если у вас открыт один ВК в качестве DNS вы должны увидеть сервер Yandex. 

ЕБОШИМ ДАЛЬШЕ и ГЛУБЖЕ - ЭТО ПРОКСИ_ТОРРЕНТ

pip3 install doh-proxy

Шо с ним делать читайте здесь:
https://facebookexperimental.github.io/doh-proxy/

А эта завидная штука для 64 разрядности:
https://github.com/softwareengineer1/YourFriendlyDNS



КАСТОМНЫЙ ФАЙЛ dnscrypt-proxy


##############################################
# #
# dnscrypt-proxy configuration #
# #
##############################################

## Это пример файла конфигурации.
## Вы должны настроить его под свои нужды и сохранить как "dnscrypt-proxy.toml"
##
## Онлайн документация доступна здесь: https://dnscrypt.info/doc



##################################
# Глобальные настройки #
##################################

## Список серверов для использования
##
## Серверы из источника "public-resolvers" (см. Ниже) могут
## можно посмотреть здесь: https://dnscrypt.info/public-servers
##
## Если эта строка закомментирована, все зарегистрированные серверы, соответствующие фильтрам require_ *
## будет использоваться.
##
## Прокси автоматически выберет самые быстрые, работающие серверы из списка.
## Удалить ведущий # первым, чтобы включить это; строки, начинающиеся с #, игнорируются.

# server_names = ['scaleway-fr', 'google', 'yandex', 'cloudflare']


## Список локальных адресов и портов для прослушивания. Может быть IPv4 и / или IPv6.
## Примечание. При использовании активации через сокет systemd выберите пустой набор (например, []).

listen_addresses = ['127.0.0.1:53', '[:: 1]: 53']


## Максимальное количество одновременных клиентских подключений для принятия

max_clients = 250


## Переключение на другого пользователя системы после создания сокетов прослушивания.
## Примечание (1): эта функция в настоящее время не поддерживается в Windows.
## Примечание (2): эта функция не совместима с активацией сокета systemd.
## Примечание (3): при использовании -pidfile каталог файла PID должен быть доступен для записи новому пользователю

# user_name = 'nobody'


## Требуются серверы (из статических + удаленных источников) для удовлетворения определенных свойств

# Используйте серверы, доступные через IPv4
ipv4_servers = true

# Используйте серверы, доступные через IPv6 - не включайте, если у вас нет подключения к IPv6
ipv6_servers = false

# Используйте серверы, реализующие протокол DNSCrypt
dnscrypt_servers = true

# Используйте серверы, реализующие протокол DNS-over-HTTPS
doh_servers = true


## Требуются серверы, определенные удаленными источниками для удовлетворения определенных свойств

# Сервер должен поддерживать расширения безопасности DNS (DNSSEC)
require_dnssec = false

# Сервер не должен регистрировать пользовательские запросы (декларативный)
require_nolog = true

# Сервер не должен применять собственный черный список (для родительского контроля, блокировки рекламы ...)
require_nofilter = true

# Имена серверов, которых следует избегать, даже если они соответствуют всем критериям
disabled_server_names = []


## Всегда используйте TCP для подключения к вышестоящим серверам.
## Это может быть полезно, если вам нужно все маршрутизировать через Tor.
## В противном случае оставьте значение false, поскольку это не повышает безопасность
## (dnscrypt-proxy всегда будет шифровать все, даже используя UDP), и может
## только увеличить задержку.

force_tcp = false


## SOCKS прокси
## Раскомментируйте следующую строку для маршрутизации всех TCP-соединений к локальному узлу Tor
## Tor не поддерживает UDP, поэтому установите `force_tcp` в` true`.

# proxy = "socks5: //127.0.0.1: 9050"


## HTTP / HTTPS прокси
## Только для серверов DoH

# http_proxy = "http://127.0.0.1:8888"


## Как долго DNS-запрос будет ждать ответа, в миллисекундах

тайм-аут = 2500


## Keepalive для запросов HTTP (HTTPS, HTTP / 2), в секундах

keepalive = 30


## Использовать ОТКАЗАННЫЙ код возврата для заблокированных ответов
## Установка этого значения в `false` означает, что некоторые ответы будут ложными.
## К сожалению, для Android 8+ требуется `false`

den_code_in_responses = false


## Стратегия балансировки нагрузки: «p2» (по умолчанию), «ph», «самый быстрый» или «случайный»

# lb_strategy = 'p2'


## Уровень журнала (0-6, по умолчанию: 2 - 0 очень подробный, 6 содержит только фатальные ошибки)

# log_level = 2


## файл журнала для приложения

# log_file = 'dnscrypt-proxy.log'


## Используйте системный журнал (системный журнал в Unix, журнал событий в Windows)

# use_syslog = true


## Задержка, в минутах, после которой сертификаты перезагружаются

cert_refresh_delay = 240


## DNSCrypt: создайте новый уникальный ключ для каждого запроса DNS
## Это может улучшить конфиденциальность, но также может оказать существенное влияние на использование процессора
## Включить только если у вас нет большой загрузки сети

# dnscrypt_ephemeral_keys = false


## DoH: отключить билеты сеанса TLS - увеличивает конфиденциальность, но также задержку

# tls_disable_session_tickets = false


## DoH: использовать определенный набор шифров вместо предпочтения сервера
## 49199 = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
## 49195 = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
## 52392 = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
## 52393 = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
##
## На процессорах не-Intel, таких как MIPS-маршрутизаторы и системы ARM (Android, Raspberry Pi ...),
## следующий набор улучшает производительность.
## Это также может помочь на процессорах Intel с 32-разрядными операционными системами.
##
## Держите tls_cipher_suite пустым, если у вас есть проблемы с загрузкой источников или
## подключение к некоторым серверам DoH. Google и Cloudflare хорошо с этим.

# tls_cipher_suite = [52392, 49199]


## Резервный распознаватель
## Это обычный незашифрованный преобразователь DNS, который будет использоваться только
## для одноразовых запросов при получении начального списка распознавателей, и
## только если система DNS не работает.
## Никакие запросы пользовательских приложений никогда не будут пропущены через этот преобразователь,
## и не будет использоваться после того, как были найдены IP-адреса URL-адресов распознавателей.
## Он никогда не будет использоваться, если списки уже были кэшированы, и если штампы
## не включать имена хостов без IP-адресов.
## Не будет использоваться, если настроенный системный DNS работает.
## Рекомендуется распознаватель, поддерживающий DNSSEC. Это может стать обязательным.
##
## Люди в Китае, возможно, должны использовать 114.114.114.114:53 здесь.
## Другие популярные опции включают 8.8.8.8 и 1.1.1.1.

fallback_resolver = '9.9.9.9:53'


## Никогда не позволяйте dnscrypt-proxy пытаться использовать системные настройки DNS;
## безоговорочно использовать резервный распознаватель.

ignore_system_dns = false


## Максимальное время (в секундах) ожидания подключения к сети, прежде чем
## инициализация прокси.
## Полезно, если прокси автоматически запускается при загрузке и сети
## подключение не гарантируется быть немедленно доступным.
## Используйте 0 для отключения.

netprobe_timeout = 60


## Автономный режим - не используйте удаленные зашифрованные серверы.
## Прокси останется полностью функциональным, чтобы отвечать на запросы, которые
## плагины могут обрабатывать напрямую (пересылка, маскировка, ...)

# offline_mode = false


## Автоматическая ротация лог файлов

# Максимальный размер файла журнала в МБ
log_files_max_size = 10

# Как долго хранить файлы резервных копий, в днях
log_files_max_age = 7

# Максимальное количество резервных копий файлов журнала (или 0, чтобы сохранить все резервные копии)
log_files_max_backups = 1



#########################
# Фильтры #
#########################

## Немедленно отвечайте на связанные с IPv6 запросы пустым ответом
## Это делает вещи быстрее, когда нет подключения к IPv6, но может
## также вызывает проблемы с надежностью некоторых обработчиков заглушек.
## Не включайте, если вы добавили проверяющий распознаватель, такой как dnsmasq, перед
## прокси.

block_ipv6 = false



################################################## ################################
# Направлять запросы для определенных доменов на выделенный набор серверов #
################################################## ################################

## Пример записей карты (одна запись в строке):
## example.com 9.9.9.9
## example.net 9.9.9.9,8.8.8.8,1.1.1.1

# forwarding_rules = 'forwarding-rules.txt'



###############################
# Правила маскировки #
###############################

## Cloaking возвращает предопределенный адрес для конкретного имени.
## Помимо работы в качестве файла HOSTS, он также может возвращать IP-адрес
## с другим именем. Также будет выполнено выравнивание CNAME.
##
## Пример записей карты (одна запись в строке)
## example.com 10.1.1.1
## www.google.com forceafesearch.google.com

# cloaking_rules = 'cloaking-rules.txt'



###########################
# DNS кеш #
###########################

## Включить DNS-кеш, чтобы уменьшить задержку и исходящий трафик

кеш = правда


## Размер кэша

cache_size = 512


## Минимальный TTL для кэшированных записей

cache_min_ttl = 600


## Максимальный TTL для кэшированных записей

cache_max_ttl = 86400


## Минимальный TTL для записей с отрицательным кэшированием

cache_neg_min_ttl = 60


## Максимальный TTL для отрицательно кэшированных записей

cache_neg_max_ttl = 600



###############################
# Журнал запросов #
###############################

## Записывать клиентские запросы в файл

[Query_log]

  ## Путь к файлу журнала запросов (абсолютный или относительно того же каталога, что и исполняемый файл)

  # file = 'query.log'


  ## Формат журнала запросов (в настоящее время поддерживается: tsv и ltsv)

  формат = 'цв'


  ## Не регистрируйте эти типы запросов, чтобы уменьшить детализацию. Оставьте пустым, чтобы войти все.

  # ignored_qtypes = ['DNSKEY', 'NS']



############################################
# Регистрация подозрительных запросов #
############################################

## Журнал запросов для несуществующих зон
## Эти запросы могут выявить наличие вредоносных программ, сломанных / устаревших приложений,
## и устройства, сигнализирующие о своем присутствии третьим лицам.

[Nx_log]

  ## Путь к файлу журнала запросов (абсолютный или относительно того же каталога, что и исполняемый файл)

  # file = 'nx.log'


  ## Формат журнала запросов (в настоящее время поддерживается: tsv и ltsv)

  формат = 'цв'



################################################## ####
Блокировка на основе шаблонов (черные списки)
################################################## ####

## Черные списки состоят из одного шаблона в строке. Пример допустимых шаблонов:
##
## example.com
## = example.com
## * секс *
## Объявления.*
## ads * .example. *
## ads * .example [0-9] *. com
##
## Примеры файлов черного списка можно найти по адресу https://download.dnscrypt.info/blacklists/
## Сценарий для создания черных списков из общедоступных каналов можно найти в
## `utils / generate-domains-blacklists` каталог исходного кода dnscrypt-proxy.

[black list]

  ## Путь к файлу правил блокировки (абсолютный или относительно того же каталога, что и исполняемый файл)

  # blacklist_file = 'blacklist.txt'


  ## Необязательный путь к файлу регистрации заблокированных запросов

  # log_file = 'заблокирован.log'


  ## Необязательный формат журнала: tsv или ltsv (по умолчанию: tsv)

  # log_format = 'tsv'



################################################## #########
# Блокировка IP на основе шаблона (черные списки IP) #
################################################## #########

## Черные списки IP состоят из одного шаблона на строку. Пример допустимых шаблонов:
##
## 127. *
## fe80: abcd: *
## 192.168.1.4

[Ip_blacklist]

  ## Путь к файлу правил блокировки (абсолютный или относительно того же каталога, что и исполняемый файл)

  # blacklist_file = 'ip-blacklist.txt'


  ## Необязательный путь к файлу регистрации заблокированных запросов

  # log_file = 'ip-заблокирован.log'


  ## Необязательный формат журнала: tsv или ltsv (по умолчанию: tsv)

  # log_format = 'tsv'



################################################## ####
# Белый список на основе шаблонов (обход черных списков) #
################################################## ####

## Белые списки поддерживают те же шаблоны, что и черные списки
## Если имя соответствует записи в белом списке, соответствующий сеанс
## будет обходить имена и IP-фильтры.
##
## Также поддерживаются правила на основе времени, чтобы сделать некоторые сайты доступными только в определенное время дня.

[white list]

  ## Путь к файлу правил белых списков (абсолютный или относительно того же каталога, что и исполняемый файл)

  # whitelist_file = 'whitelist.txt'


  ## Необязательный путь к файлу регистрации запросов из белого списка

  # log_file = 'whitelisted.log'


  ## Необязательный формат журнала: tsv или ltsv (по умолчанию: tsv)

  # log_format = 'tsv'



##########################################
# Ограничение времени доступа #
##########################################

## Здесь можно определить одно или несколько еженедельных расписаний.
## За шаблонами в блочном списке, основанном на имени, необязательно может следовать @schedule_name
## применять шаблон «имя_программы» только тогда, когда он соответствует временному диапазону этого расписания.
##
## Например, следующее правило в файле черного списка:
## * .youtube. * @ время сна
## блокирует доступ к YouTube только в течение дней и периода дней
## определить по графику «время сна».
##
## {after = '21: 00 ', before =' 7:00 '} соответствует 0: 00-7: 00 и 21: 00-0: 00
## {after = '9:00', before = '18: 00 '} соответствует 9: 00-18: 00

[schedules]

  # [schedules.'time-to-sleep ']
  # mon = [{after = '21: 00 ', before =' 7: 00 '}]
  # вт = [{после = '21:00', до = '7:00'}]
  # wed = [{after = '21: 00 ', before =' 7: 00 '}]
  # thu = [{after = '21: 00 ', before =' 7: 00 '}]
  # fri = [{after = '23: 00 ', before =' 7: 00 '}]
  # sat = [{after = '23: 00 ', before =' 7: 00 '}]
  # sun = [{after = '21: 00', before = '7: 00'}]

  # [schedules.'work ']
  # mon = [{after = '9: 00', before = '18: 00 '}]
  # вт = [{после = '9: 00', до = '18: 00 '}]
  # wed = [{after = '9: 00', before = '18: 00 '}]
  # thu = [{after = '9: 00', before = '18: 00 '}]
  # fri = [{after = '9: 00', before = '17: 00 '}]



#########################
# Серверы #
#########################

## Удаленные списки доступных серверов
## Несколько источников могут быть использованы одновременно, но каждый источник
## требуется выделенный файл кэша.
##
## Обратитесь к документации для получения ссылок на общедоступные источники.
##
## Префикс может быть добавлен перед именами серверов, чтобы
## избегать коллизий, если разные источники делят одно и то же для
## разные серверы. В этом случае имена перечислены в `server_names`
## должен включать префиксы.
##
## Если свойство `urls` отсутствует, кэшируйте файлы и действительные подписи
## должен уже присутствовать; Это не мешает этим файлам кэша
## истекает через `refresh_delay` часов.

[sources]

  ## Пример удаленного источника с https://github.com/DNSCrypt/dnscrypt-resolvers

  [sources.'public-резольверы]
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/public-resolvers.md', 'https://download.dnscrypt.info/resolvers-list/v2/public- resolvers.md ']
  cache_file = 'public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
  refresh_delay = 72
  префикс = ''

  ## Quad9 через DNSCrypt - https://quad9.net/

  # [sources.quad9-resolvers]
  # urls = ["https://www.quad9.net/quad9-resolvers.md"]
  # minisign_key = "RWQBphd2 + f6eiAqBsvDZEBXBGHQBJfeG6G + wJPPKxCZMoEQYpmoysKUN"
  # cache_file = "quad9-resolvers.md"
  # refresh_delay = 72
  # prefix = "quad9-"

  ## Еще один пример источника с распознавателями, которые цензурируют некоторые веб-сайты, не предназначенные для детей.
  ## Это подмножество списка `public-resolvers`, поэтому включение обоих бесполезно

  # [sources.'parental-control ']
  # urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v2/parental-control.md', 'https://download.dnscrypt.info/resolvers-list/v2/parental -control.md ']
  # cache_file = 'parental-control.md'
  # minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'



## Необязательный, локальный, статический список дополнительных серверов
## Полезно для тестирования ваших собственных серверов.

[static]

  # [static.'google ']
  # stamp = 'sdns: // AgUAAAAAAAAAAAAOZG5zLmdvb2dsZS5jb20NL2V4cGVyaW1lbnRhbA'
