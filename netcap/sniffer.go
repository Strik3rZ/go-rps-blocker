package netcap

import (
    "log"
    "sync"
    "time"
	"strconv"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"

    "go-rps-blocker/block"
    "go-rps-blocker/config"
)

// Sniffer отвечает за захват пакетов и логику RPS
type Sniffer struct {
    cfg      *config.Config
    blocker  *block.Blocker
    handle   *pcap.Handle
    stopCh   chan struct{}
    wg       sync.WaitGroup

    packetCount map[string]int
    mutex       sync.Mutex
}

// NewSniffer создаёт новый Sniffer
func NewSniffer(cfg *config.Config, blocker *block.Blocker) *Sniffer {
    return &Sniffer{
        cfg:         cfg,
        blocker:     blocker,
        stopCh:      make(chan struct{}),
        packetCount: make(map[string]int),
    }
}

// Start запускает захват пакетов и периодическую проверку
func (s *Sniffer) Start() error {
    // Открываем интерфейс
    handle, err := pcap.OpenLive(
        s.cfg.Device,
        int32(s.cfg.SnapshotLen),
        s.cfg.Promiscuous,
        s.cfg.Timeout,
    )
    if err != nil {
        return err
    }
    s.handle = handle

    // Устанавливаем BPF-фильтр, если указан порт
    if s.cfg.Port != 0 {
        filter :=  "port " +  ics(s.cfg.Port)
        err = s.handle.SetBPFFilter(filter)
        if err != nil {
            return err
        }
        log.Printf("Применён BPF-фильтр: %q\n", filter)
    } else {
        // никакого фильтра => слушаем весь трафик
        log.Println("BPF-фильтр не применяется, слушаем весь трафик")
    }

    // Создаём PacketSource
    packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())

    // Горутинa для чтения пакетов
    s.wg.Add(1)
    go func() {
        defer s.wg.Done()
        s.runPacketLoop(packetSource)
    }()

    // Горутинa для периодической проверки RPS
    s.wg.Add(1)
    go func() {
        defer s.wg.Done()
        s.runTicker()
    }()

    return nil
}

// runPacketLoop читает пакеты из packetSource, пока не получит сигнал остановки
func (s *Sniffer) runPacketLoop(packetSource *gopacket.PacketSource) {
    for {
        select {
        case packet, ok := <-packetSource.Packets():
            if !ok {
                // канал закрылся
                return
            }
            s.processPacket(packet)
        case <-s.stopCh:
            return
        }
    }
}

// processPacket инкрементирует счётчик для src IP
func (s *Sniffer) processPacket(packet gopacket.Packet) {
    // Для примера обрабатываем IPv4
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer == nil {
        return
    }
    ip, ok := ipLayer.(*layers.IPv4)
    if !ok {
        return
    }
    srcIP := ip.SrcIP.String()

    // Проверяем whitelist/blocked
    if s.blocker.IsWhitelisted(srcIP) || s.blocker.IsBlocked(srcIP) {
        // Не учитываем в статистике
        return
    }

    s.mutex.Lock()
    s.packetCount[srcIP]++
    s.mutex.Unlock()
}

// runTicker каждые cfg.TickerInterval проверяет счётчики и блокирует, если нужно
func (s *Sniffer) runTicker() {
    ticker := time.NewTicker(s.cfg.TickerInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ticker.C:
            s.checkAndBlock()
        case <-s.stopCh:
            return
        }
    }
}

// checkAndBlock смотрит, у кого счётчик выше threshold, и вызывает блокировку
func (s *Sniffer) checkAndBlock() {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    for ip, count := range s.packetCount {
        if count > s.cfg.Threshold {
            // Блокируем IP
            // BlockIP() сам проверит whitelist и т.д.
            if err := s.blocker.BlockIP(ip); err != nil {
                log.Printf("[Sniffer] Ошибка блокировки IP %s: %v", ip, err)
            }
        }
    }
    // Сбрасываем счётчики на новый интервал
    s.packetCount = make(map[string]int)
}

// Stop останавливает горутины и закрывает pcap
func (s *Sniffer) Stop() {
    close(s.stopCh)
    s.wg.Wait()

    if s.handle != nil {
        s.handle.Close()
    }
}

func ics(port uint16) string {
    return strconv.Itoa(int(port))
}