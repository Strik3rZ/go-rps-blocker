package config

import (
    "bufio"
    "flag"
    "fmt"
    "os"
    "strings"
    "time"
)

// Config содержит все параметры, нужные для запуска
type Config struct {
    Device         string
    SnapshotLen    int
    Promiscuous    bool
    Timeout        time.Duration
    Threshold      int
    WhitelistFile  string
    BlockedIPFile  string
    TickerInterval time.Duration
    Port           uint16 // Порт, который надо слушать (0 = все)
    WhitelistIPs   map[string]bool
}

// LoadConfig загружает конфигурацию (из флагов, файлов и т.д.)
func LoadConfig() (*Config, error) {
    cfg := &Config{}

    // Флаги для CLI
    flag.StringVar(&cfg.Device, "device", "eth0", "Сетевой интерфейс для прослушивания")
    flag.IntVar(&cfg.SnapshotLen, "snapshotlen", 1024, "Размер snapshot (байт) для pcap")
    flag.BoolVar(&cfg.Promiscuous, "promisc", true, "Включать режим promiscuous")
    // Условно, можно задать cfg.Timeout как pcap.BlockForever, но для наглядности
    flag.DurationVar(&cfg.Timeout, "timeout", 0, "Таймаут pcap (0 = BlockForever)")
    flag.IntVar(&cfg.Threshold, "threshold", 100, "Порог пакетов в секунду, выше которого IP блокируется")
    flag.StringVar(&cfg.WhitelistFile, "whitelist", "/tmp/whitelist_ips.txt", "Путь к файлу с whitelist IP")
    flag.StringVar(&cfg.BlockedIPFile, "blocked", "/tmp/blocked_ips.txt", "Путь к файлу, куда писать заблокированные IP")
    flag.DurationVar(&cfg.TickerInterval, "interval", time.Second, "Интервал проверки счетчика (RPS)")
    // Порт 0 => слушаем все порты
    var port uint
    flag.UintVar(&port, "port", 0, "TCP/UDP порт, который надо слушать (0 = все)")
    
    flag.Parse()

    cfg.Port = uint16(port)

    // Инициализируем карту whitelist
    whitelist, err := loadWhitelistFile(cfg.WhitelistFile)
    if err != nil {
        // Если файла нет, не падаем, но предупреждаем
        fmt.Fprintf(os.Stderr, "Предупреждение: не удалось загрузить whitelist: %v\n", err)
    }
    cfg.WhitelistIPs = whitelist

    return cfg, nil
}

// loadWhitelistFile читает список IP-адресов из файла и формирует map[string]bool
func loadWhitelistFile(path string) (map[string]bool, error) {
    m := make(map[string]bool)

    f, err := os.Open(path)
    if err != nil {
        return m, err
    }
    defer f.Close()

    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line == "" {
            continue
        }
        m[line] = true
    }
    if err := scanner.Err(); err != nil {
        return m, err
    }
    return m, nil
}
