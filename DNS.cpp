#include "DNS_Classes.cpp"


int main() {
    // Налаштування параметрів для DNSProxyServer
    std::string upstreamDNS = "8.8.8.8"; // Адреса upstream DNS-сервера (наприклад, Google DNS)
    int port = 5353; // Порт, на якому буде працювати проксі-сервер
    std::string blacklistFile = "blacklist.txt"; // Файл чорного списку

    try {
        // Створення і запуск DNSProxyServer
        DNSProxyServer proxyServer(upstreamDNS, port, blacklistFile);
        proxyServer.startServer();
    } catch (const std::exception& e) {
        std::cerr << "Failed to start DNS Proxy Server: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}