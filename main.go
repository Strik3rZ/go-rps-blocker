package main

import (
    "log"
    "os"
    "os/signal"
    "syscall"

    "go-rps-blocker/block"
    "go-rps-blocker/config"
    "go-rps-blocker/netcap"
)

func main() {
    // 1) Загружаем конфигурацию (параметры, whitelist и т.д.)
    cfg, err := config.LoadConfig()
    if err != nil {
        log.Fatalf("Ошибка загрузки конфигурации: %v", err)
    }

    // 2) Инициализируем blocker (белый список, файл для блокировки и т.д.)
    bl := block.NewBlocker(cfg)

    // 3) Запускаем сниффер, который собирает пакеты, считает RPS и вызывает "блокирующую" логику
    sniffer := netcap.NewSniffer(cfg, bl)
    if err := sniffer.Start(); err != nil {
        log.Fatalf("Ошибка запуска сниффера: %v", err)
    }

    // Ловим сигналы ОС, чтобы корректно завершиться
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

    log.Println("Сервис запущен. Ожидаем пакетов...")

    // Ожидаем сигнала, по которому завершим работу
    <-sigChan
    log.Println("Получен сигнал завершения. Останавливаемся...")

    // Корректно останавливаем сниффер
    sniffer.Stop()
}
