#ifndef MYHEADER_H
#define MYHEADER_H

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_set>
#include <stdexcept>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>

// // Клас для роботи з чорним списком доменів
// class Blacklist {
// public:
//     bool isBlacklisted(const std::string& domain) const;
//     void addDomain(const std::string& domain);
//     void removeDomain(const std::string& domain);
//     void load(const std::string& filename);

// private:
//     std::unordered_set<std::string> blacklist;
// };

// bool Blacklist::isBlacklisted( const std::string & domain ) const
// {
//       return blacklist.find(domain) != blacklist.end();
// }

// void Blacklist::addDomain( const std::string & domain )
// {
//     if ( ! domain.empty() )
//         blacklist.insert( domain );
//     else
//         std::cout << " domain is empty " << std::endl;
// }

// void Blacklist::load(const std::string& filename) {
//     std::ifstream file(filename);
//     if (!file.is_open()) {
//         throw std::runtime_error("Failed to open blacklist file");
//     }

//     std::string domain;
//     while (std::getline(file, domain)) {
//         blacklist.insert(domain);
//     }

//     file.close();
// }

// void Blacklist::removeDomain( const std::string & domain )
// {
//     auto it = std::find_if(blacklist.begin(), blacklist.end(), [domain](const std::string domin) 
//     {
//         return domin == domain;
//     });

//     if ( it != blacklist.end() )
//     {
//         blacklist.erase( it );
//     }
//     else
//     {
//         std::cout << " domain is not in the list " << std::endl;
//     }
// }










// // Клас для роботи з DNS-запитами
// class DNSRequest {
// public:
//     DNSRequest(const std::vector<char>& data);
//     std::string getDomainName() const;
//     void parseRequest();
//     std::string parseQueryName(const std::vector<char>& data, size_t& offset);

//     std::vector<char> & getRequestData();

// private:
//     std::vector<char> requestData;
//     std::string domainName;
// };

// // Конструктор, що приймає DNS-запит у вигляді масиву байтів
// DNSRequest::DNSRequest(const std::vector<char>& data) : requestData(data) {
//     parseRequest();
// }

// // Метод для розбору DNS-запиту
// void DNSRequest::parseRequest() {
//     if (requestData.size() < sizeof(uint16_t) * 6) {
//         throw std::runtime_error("Invalid DNS request: header too short");
//     }

//     // Пропускаємо заголовок
//     size_t offset = sizeof(uint16_t) * 6;

//     // Розбираємо питання (доменне ім'я)
//     domainName = parseQueryName(requestData, offset);
// }

// // Метод для розбору доменного імені в DNS-запиті
// std::string DNSRequest::parseQueryName(const std::vector<char>& data, size_t& offset) {
//     std::string name;
//     while (data[offset] != 0) {
//         uint8_t length = data[offset];
//         if (offset + length + 1 > data.size()) {
//             throw std::runtime_error("Invalid DNS request: query name too long");
//         }
//         if (!name.empty()) {
//             name += '.';
//         }
//         name.append(&data[offset + 1], length);
//         offset += length + 1;
//     }
//     offset += 1; // Пропускаємо нульовий байт
//     return name;
// }


// std::string DNSRequest::getDomainName() const
// {
//     return domainName;
// }

// std::vector<char>& DNSRequest::getRequestData()
// {
//     return requestData;
// }











// // Клас для роботи з DNS-відповідями
// class DNSResponse {
// public:
//     DNSResponse();
//     std::vector<char> createBlockedResponse( DNSRequest& request);
//     void parseResponse( const std::vector<char>& data);

// private:
//     std::vector<char> responseData;
// };


// // Конструктор
// DNSResponse::DNSResponse() {}

// std::vector<char> DNSResponse::createBlockedResponse(  DNSRequest& request )
// {
//     std::vector<char> response;

//     // Заголовок відповіді (копіюємо ID із запиту, встановлюємо прапорці)
//     response.push_back(request.getRequestData()[0]); // ID (1 байт)
//     response.push_back(request.getRequestData()[1]); // ID (2 байт)
//     response.push_back(0x81); // Прапорці: QR=1, Opcode=0, AA=1, TC=0, RD=1
//     response.push_back(0x83); // Прапорці: RA=1, Z=0, AD=0, CD=0, RCODE=3 (NXDOMAIN)
    
//     // Питання та відповіді
//     response.insert(response.end(), request.getRequestData().begin() + 4, request.getRequestData().begin() + 12); // Кількість питань та відповідей
    
//     // Копіюємо питання (включно з доменним ім'ям та типом/класом)
//     response.insert(response.end(), request.getRequestData().begin() + 12, request.getRequestData().end());

//     return response;
// }

// void DNSResponse::parseResponse( const std::vector<char>& data )
// {
//     responseData = data;

//     // Розбір заголовка
//     if (responseData.size() < sizeof(uint16_t) * 6) {
//         throw std::runtime_error("Invalid DNS response: header too short");
//     }

//     // Пропускаємо заголовок
//     // size_t offset = sizeof(uint16_t) * 6;


//     size_t offset = 0;

//     // Зчитуємо ID запиту
//     uint16_t id = (responseData[offset] << 8) | responseData[offset + 1];
//     offset += 2;

//     // Зчитуємо прапорці
//     uint16_t flags = (responseData[offset] << 8) | responseData[offset + 1];
//     offset += 2;

//     // Зчитуємо кількість запитань
//     uint16_t qdcount = (responseData[offset] << 8) | responseData[offset + 1];
//     offset += 2;

//     // Зчитуємо кількість відповідей
//     uint16_t ancount = (responseData[offset] << 8) | responseData[offset + 1];
//     offset += 2;

//     // Зчитуємо кількість записів авторитетних серверів
//     uint16_t nscount = (responseData[offset] << 8) | responseData[offset + 1];
//     offset += 2;

//     // Зчитуємо кількість додаткових записів
//     uint16_t arcount = (responseData[offset] << 8) | responseData[offset + 1];
//     offset += 2;


//  // Розбір питань
//     for (int i = 0; i < qdcount; ++i) {
//         std::string qname;
//         while (responseData[offset] != 0) {
//             int len = responseData[offset];
//             qname.append(responseData.begin() + offset + 1, responseData.begin() + offset + 1 + len);
//             qname.append(".");
//             offset += len + 1;
//         }
//         qname.pop_back(); // видаляємо останню крапку
//         offset += 1;

//         uint16_t qtype = (responseData[offset] << 8) | responseData[offset + 1];
//         offset += 2;
//         uint16_t qclass = (responseData[offset] << 8) | responseData[offset + 1];
//         offset += 2;

//         std::cout << "Question: " << qname << " Type: " << qtype << " Class: " << qclass << std::endl;
//     }

//     // Розбір відповідей
//     for (int i = 0; i < ancount; ++i) {
//         std::string rname;
//         while (responseData[offset] != 0) {
//             int len = responseData[offset];
//             rname.append(responseData.begin() + offset + 1, responseData.begin() + offset + 1 + len);
//             rname.append(".");
//             offset += len + 1;
//         }
//         rname.pop_back(); // видаляємо останню крапку
//         offset += 1;

//         uint16_t rtype = (responseData[offset] << 8) | responseData[offset + 1];
//         offset += 2;
//         uint16_t rclass = (responseData[offset] << 8) | responseData[offset + 1];
//         offset += 2;
//         uint32_t ttl = (responseData[offset] << 24) | (responseData[offset + 1] << 16) | (responseData[offset + 2] << 8) | responseData[offset + 3];
//         offset += 4;
//         uint16_t rdlength = (responseData[offset] << 8) | responseData[offset + 1];
//         offset += 2;

//         std::vector<char> rdata(responseData.begin() + offset, responseData.begin() + offset + rdlength);
//         offset += rdlength;

//         std::cout << "Answer: " << rname << " Type: " << rtype << " Class: " << rclass << " TTL: " << ttl << " RDLENGTH: " << rdlength << std::endl;
//     }

// }






// // Клас для роботи з DNS-проксі сервером
// class DNSProxyServer {
// public:
//     DNSProxyServer(const std::string& upstreamDNS, int port);
//     void startServer();

// private:
//     void processRequest(int clientSocket);
//     std::vector<char> forwardRequest( DNSRequest& request);
//     void sendResponse(int serverSocket, const std::vector<char>& response, const sockaddr_in& clientAddr);
//     void loadBlacklist(const std::string& filename);

//     std::string upstreamDNS;
//     int port;
//     Blacklist blacklist;
// };

// // Конструктор
// DNSProxyServer::DNSProxyServer(const std::string& upstreamDNS, int port)
//     : upstreamDNS(upstreamDNS), port(port) {}

// void DNSProxyServer::startServer()
// {
//     int serverSocket = socket(AF_INET, SOCK_DGRAM, 0);
//     if (serverSocket < 0) {
//         throw std::runtime_error("Failed to create socket");
//     }

//     sockaddr_in serverAddr{};
//     serverAddr.sin_family = AF_INET;
//     serverAddr.sin_addr.s_addr = INADDR_ANY;
//     serverAddr.sin_port = htons(port);

//     if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
//         throw std::runtime_error("Failed to bind socket");
//     }

//     while (true) {
//         sockaddr_in clientAddr{};
//         socklen_t clientAddrLen = sizeof(clientAddr);
//         std::vector<char> buffer(512);

//         int received = recvfrom(serverSocket, buffer.data(), buffer.size(), 0, (struct sockaddr*)&clientAddr, &clientAddrLen);
//         if (received < 0) {
//             std::cerr << "Failed to receive data" << std::endl;
//             continue;
//         }

//         buffer.resize(received);
//         DNSRequest request(buffer);

//         if (blacklist.isBlacklisted(request.getDomainName())) {
//             std::vector<char> response = DNSResponse().createBlockedResponse(request);
//             sendResponse(serverSocket, response, clientAddr);
//         } else {
//             std::vector<char> response = forwardRequest(request);
//             sendResponse(serverSocket, response, clientAddr);
//         }
//     }

//     close(serverSocket);
// }



// // Обробка запиту
// void DNSProxyServer::processRequest(int clientSocket) {
//     // Реалізація тут
// }



// // Перенаправлення запиту до справжнього DNS-сервера
// std::vector<char> DNSProxyServer::forwardRequest( DNSRequest& request) {
//     int sock = socket(AF_INET, SOCK_DGRAM, 0);
//     if (sock < 0) {
//         throw std::runtime_error("Failed to create socket");
//     }

//     sockaddr_in dnsServerAddr{};
//     dnsServerAddr.sin_family = AF_INET;
//     dnsServerAddr.sin_port = htons(53);
//     inet_pton(AF_INET, upstreamDNS.c_str(), &dnsServerAddr.sin_addr);

//     sendto(sock, request.getRequestData().data(), request.getRequestData().size(), 0, (struct sockaddr*)&dnsServerAddr, sizeof(dnsServerAddr));

//     std::vector<char> buffer(512);
//     int received = recvfrom(sock, buffer.data(), buffer.size(), 0, nullptr, nullptr);
//     if (received < 0) {
//         close(sock);
//         throw std::runtime_error("Failed to receive data from upstream DNS server");
//     }

//     buffer.resize(received);
//     close(sock);
//     return buffer;
// }



// // Відправка відповіді клієнту
// void DNSProxyServer::sendResponse(int serverSocket, const std::vector<char>& response, const sockaddr_in& clientAddr) {
//     sendto(serverSocket, response.data(), response.size(), 0, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
// }

// // Завантаження чорного списку
// void DNSProxyServer::loadBlacklist(const std::string& filename) {
//     blacklist.load(filename);
// }

































































// Клас для роботи з чорним списком доменів
class Blacklist {
public:
    bool isBlacklisted(const std::string& domain) const;
    void addDomain(const std::string& domain);
    void removeDomain(const std::string& domain);
    void load(const std::string& filename);

private:
    std::unordered_set<std::string> blacklist;
};

bool Blacklist::isBlacklisted(const std::string& domain) const {
    return blacklist.find(domain) != blacklist.end();
}

void Blacklist::addDomain(const std::string& domain) {
    if (!domain.empty())
        blacklist.insert(domain);
    else
        std::cout << "Domain is empty" << std::endl;
}

void Blacklist::removeDomain(const std::string& domain) {
    auto it = blacklist.find(domain);
    if (it != blacklist.end())
        blacklist.erase(it);
    else
        std::cout << "Domain not found in blacklist" << std::endl;
}

void Blacklist::load(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open blacklist file");
    }

    std::string domain;
    while (std::getline(file, domain)) {
        blacklist.insert(domain);
    }

    file.close();
}







// Клас для роботи з DNS-запитами
class DNSRequest {
public:
    DNSRequest(const std::vector<char>& data);
    std::string getDomainName() const;
    void parseRequest();
    std::vector<char>& getRequestData();

private:
    std::vector<char> requestData;
    std::string domainName;
};

DNSRequest::DNSRequest(const std::vector<char>& data) : requestData(data) {
    parseRequest();
}

void DNSRequest::parseRequest() {
    if (requestData.size() < sizeof(uint16_t) * 6) {
        throw std::runtime_error("Invalid DNS request: header too short");
    }

    size_t offset = sizeof(uint16_t) * 6;
    while (requestData[offset] != 0) {
        uint8_t length = requestData[offset];
        if (offset + length + 1 > requestData.size()) {
            throw std::runtime_error("Invalid DNS request: query name too long");
        }
        if (!domainName.empty()) {
            domainName += '.';
        }
        domainName.append(&requestData[offset + 1], length);
        offset += length + 1;
    }
    domainName.pop_back(); // Remove the last dot
    offset += 1; // Skip the null byte
}

std::string DNSRequest::getDomainName() const {
    return domainName;
}

std::vector<char>& DNSRequest::getRequestData()
{
    return requestData;
}





// Клас для роботи з DNS-відповідями
class DNSResponse {
public:
    DNSResponse();
    std::vector<char> createBlockedResponse( DNSRequest& request);
    void parseResponse(const std::vector<char>& data);

private:
    std::vector<char> responseData;
};

DNSResponse::DNSResponse() {}

std::vector<char> DNSResponse::createBlockedResponse( DNSRequest& request) {
    std::vector<char> response;
    response.push_back(request.getRequestData()[0]); // ID (1 byte)
    response.push_back(request.getRequestData()[1]); // ID (2 bytes)
    response.push_back(0x81); // Flags: QR=1, Opcode=0, AA=1, TC=0, RD=1
    response.push_back(0x83); // Flags: RA=1, Z=0, AD=0, CD=0, RCODE=3 (NXDOMAIN)
    response.insert(response.end(), request.getRequestData().begin() + 4, request.getRequestData().begin() + 12); // Questions and answers count
    response.insert(response.end(), request.getRequestData().begin() + 12, request.getRequestData().end());
    return response;
}









void DNSResponse::parseResponse(const std::vector<char>& data) {
    responseData = data;
    size_t offset = 0;
    uint16_t id = (responseData[offset] << 8) | responseData[offset + 1];
    offset += 2;
    uint16_t flags = (responseData[offset] << 8) | responseData[offset + 1];
    offset += 2;
    uint16_t qdcount = (responseData[offset] << 8) | responseData[offset + 1];
    offset += 2;
    uint16_t ancount = (responseData[offset] << 8) | responseData[offset + 1];
    offset += 2;
    uint16_t nscount = (responseData[offset] << 8) | responseData[offset + 1];
    offset += 2;
    uint16_t arcount = (responseData[offset] << 8) | responseData[offset + 1];
    offset += 2;

    for (int i = 0; i < qdcount; ++i) {
        std::string qname;
        while (responseData[offset] != 0) {
            int len = responseData[offset];
            qname.append(responseData.begin() + offset + 1, responseData.begin() + offset + 1 + len);
            qname.append(".");
            offset += len + 1;
        }
        qname.pop_back();
        offset += 1;
        uint16_t qtype = (responseData[offset] << 8) | responseData[offset + 1];
        offset += 2;
        uint16_t qclass = (responseData[offset] << 8) | responseData[offset + 1];
        offset += 2;
        std::cout << "Question: " << qname << " Type: " << qtype << " Class: " << qclass << std::endl;
    }

    for (int i = 0; i < ancount; ++i) {
        std::string rname;
        while (responseData[offset] != 0) {
            int len = responseData[offset];
            rname.append(responseData.begin() + offset + 1, responseData.begin() + offset + 1 + len);
            rname.append(".");
            offset += len + 1;
        }
        rname.pop_back();
        offset += 1;
        uint16_t rtype = (responseData[offset] << 8) | responseData[offset + 1];
        offset += 2;
        uint16_t rclass = (responseData[offset] << 8) | responseData[offset + 1];
        offset += 2;
        uint32_t ttl = (responseData[offset] << 24) | (responseData[offset + 1] << 16) | (responseData[offset + 2] << 8) | responseData[offset + 3];
        offset += 4;
        uint16_t rdlength = (responseData[offset] << 8) | responseData[offset + 1];
        offset += 2;
        std::vector<char> rdata(responseData.begin() + offset, responseData.begin() + offset + rdlength);
        offset += rdlength;
        std::cout << "Answer: " << rname << " Type: " << rtype << " Class: " << rclass << " TTL: " << ttl << " RDLENGTH: " << rdlength << std::endl;
    }
}
















// Клас для роботи з DNS-проксі сервером
class DNSProxyServer {
public:
    DNSProxyServer(const std::string& upstreamDNS, int port, const std::string& blacklistFile);
    void startServer();

private:
    void processRequest(int clientSocket, const std::vector<char>& requestBuffer, const sockaddr_in& clientAddr);
    std::vector<char> forwardRequest( DNSRequest& request);
    void sendResponse(int serverSocket, const std::vector<char>& response, const sockaddr_in& clientAddr);
    void loadBlacklist(const std::string& filename);

    std::string upstreamDNS;
    int port;
    Blacklist blacklist;
};

DNSProxyServer::DNSProxyServer(const std::string& upstreamDNS, int port, const std::string& blacklistFile)
    : upstreamDNS(upstreamDNS), port(port) {
    loadBlacklist(blacklistFile);
}

void DNSProxyServer::startServer() {
    int serverSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (serverSocket < 0) {
        throw std::runtime_error("Failed to create socket");
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        close(serverSocket);
        throw std::runtime_error("Failed to bind socket");
    }

    while (true) {
        sockaddr_in clientAddr{};
        socklen_t clientAddrLen = sizeof(clientAddr);
        std::vector<char> buffer(512);

        int received = recvfrom(serverSocket, buffer.data(), buffer.size(), 0, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (received < 0) {
            std::cerr << "Failed to receive data" << std::endl;
            continue;
        }

        buffer.resize(received);
        processRequest(serverSocket, buffer, clientAddr);
    }

    close(serverSocket);
}

void DNSProxyServer::processRequest(int clientSocket, const std::vector<char>& requestBuffer, const sockaddr_in& clientAddr) {
    try {
        DNSRequest request(requestBuffer);

        if (blacklist.isBlacklisted(request.getDomainName())) {
            DNSResponse response;
            std::vector<char> blockedResponse = response.createBlockedResponse(request);
            sendResponse(clientSocket, blockedResponse, clientAddr);
        } else {
            std::vector<char> upstreamResponse = forwardRequest(request);
            sendResponse(clientSocket, upstreamResponse, clientAddr);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error processing request: " << e.what() << std::endl;
    }
}

std::vector<char> DNSProxyServer::forwardRequest( DNSRequest& request) {
    int upstreamSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (upstreamSocket < 0) {
        throw std::runtime_error("Failed to create upstream socket");
    }

    sockaddr_in upstreamAddr{};
    upstreamAddr.sin_family = AF_INET;
    upstreamAddr.sin_port = htons(53);
    inet_pton(AF_INET, upstreamDNS.c_str(), &upstreamAddr.sin_addr);

    sendto(upstreamSocket, request.getRequestData().data(), request.getRequestData().size(), 0, (struct sockaddr*)&upstreamAddr, sizeof(upstreamAddr));

    std::vector<char> responseBuffer(512);
    int received = recvfrom(upstreamSocket, responseBuffer.data(), responseBuffer.size(), 0, nullptr, nullptr);
    if (received < 0) {
        close(upstreamSocket);
        throw std::runtime_error("Failed to receive response from upstream DNS server");
    }

    responseBuffer.resize(received);
    close(upstreamSocket);
    return responseBuffer;
}

void DNSProxyServer::sendResponse(int serverSocket, const std::vector<char>& response, const sockaddr_in& clientAddr) {
    sendto(serverSocket, response.data(), response.size(), 0, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
}

void DNSProxyServer::loadBlacklist(const std::string& filename) {
    blacklist.load(filename);
}






#endif  // MYHEADER_H