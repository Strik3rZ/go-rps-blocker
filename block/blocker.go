package block

import (
    "bufio"
    "fmt"
    "log"
    "os"
    "os/exec"
    "sync"

    "go-rps-blocker/config"
)

// Blocker отвечает за блокировку IP (iptables), хранение whitelist и уже заблокированных IP
type Blocker struct {
    cfg         *config.Config
    blockedIPs  map[string]bool
    mutex       sync.Mutex
}

// NewBlocker создаёт новый Blocker
func NewBlocker(cfg *config.Config) *Blocker {
    return &Blocker{
        cfg:        cfg,
        blockedIPs: make(map[string]bool),
    }
}

// IsWhitelisted проверяет, есть ли IP в whitelist
func (b *Blocker) IsWhitelisted(ip string) bool {
    b.mutex.Lock()
    defer b.mutex.Unlock()

    return b.cfg.WhitelistIPs[ip]
}

// IsBlocked проверяет, заблокирован ли уже IP
func (b *Blocker) IsBlocked(ip string) bool {
    b.mutex.Lock()
    defer b.mutex.Unlock()

    return b.blockedIPs[ip]
}

// BlockIP вызывает iptables для блокировки IP и записывает в файл
func (b *Blocker) BlockIP(ip string) error {
    b.mutex.Lock()
    defer b.mutex.Unlock()

    // Уже заблокирован?
    if b.blockedIPs[ip] {
        return nil
    }
    // И в любом случае не блокируем, если он в whitelist
    if b.cfg.WhitelistIPs[ip] {
        return nil
    }

    log.Printf("[Blocker] Блокируем IP %s...\n", ip)

    // Пример вызова iptables:
    // iptables -A INPUT -s <ip> -j DROP
    cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("ошибка выполнения iptables: %w", err)
    }

    // Помечаем как заблокированный
    b.blockedIPs[ip] = true

    // Дописываем в файл
    if err := appendToFile(b.cfg.BlockedIPFile, ip); err != nil {
        return fmt.Errorf("ошибка записи в файл заблокированных: %w", err)
    }

    return nil
}

// appendToFile добавляет строку (IP) в текстовый файл
func appendToFile(filename, ip string) error {
    f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return err
    }
    defer f.Close()

    w := bufio.NewWriter(f)
    if _, err := w.WriteString(ip + "\n"); err != nil {
        return err
    }
    return w.Flush()
}
