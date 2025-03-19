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
    cfg, err := config.LoadConfig()
    if err != nil {
        log.Fatalf("Ошибка загрузки конфигурации: %v", err)
    }

    bl := block.NewBlocker(cfg)

    sniffer := netcap.NewSniffer(cfg, bl)
    if err := sniffer.Start(); err != nil {
        log.Fatalf("Ошибка запуска сниффера: %v", err)
    }

    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

    log.Println("Сервис запущен. Ожидаем пакетов...")

    <-sigChan
    log.Println("Получен сигнал завершения. Останавливаемся...")

    sniffer.Stop()
}
