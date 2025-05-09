#include <bits/stdc++.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <cassert>

using namespace std;

// funckje z wykladu
uint16_t compute_icmp_checksum(const void *buff, int length) {
    const uint16_t* ptr = reinterpret_cast<const uint16_t*>(buff);
    uint32_t sum = 0; 
    assert(length % 2 == 0);
    for (; length > 0; length -= 2)
        sum += *ptr++;
    sum = (sum >> 16U) + (sum & 0xffffU);
    return ~(sum + (sum >> 16U));
}

void ERROR(const char* str) {
    cerr << str << ": " << strerror(errno) << endl;
    exit(EXIT_FAILURE);
}

void print_as_bytes(unsigned char* buff, ssize_t length) {
    for (ssize_t i = 0; i < length; i++, buff++)
        printf("%.2x ", *buff);
    printf("\n");
}

// maly struct na trzymanie danych dla kazdego pakietu 
struct Packet {
    bool received;
    double rtt;
    string ip_response;
};

// zmienne globalne dla programu
int MAX_TTL = 30;
int PACKETS_TTL = 3;
uint16_t MY_ID = getpid() & 0xFFFF;
int SEQ = 1;
bool TARGET_REACHED = false;
int WAITING_TIME = 1000;

int main(int argc, char* argv[]) {
    if(argc != 2) {
        cerr << " Wywolujemy program tylko z jedna zmienna ./traceroute <xxx.xxx.xxx.xxx> \n";
        return EXIT_FAILURE;
    }

    // kod z wykladu
    // tworzenie gniazda surowego
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(sockfd < 0) {
        ERROR("error przy socket");
    } 

    // kod z wykladu
    // adres odbierajacego
    struct sockaddr_in recipient;
    memset(&recipient, 0, sizeof(recipient));
    recipient.sin_family = AF_INET;
    // 0 - nie valid ip , -1 jakis error
    if(inet_pton(AF_INET, argv[1], &recipient.sin_addr) != 1) {
        cerr << "niepoporwany adres ip :c" << endl;
        close(sockfd);
        return EXIT_FAILURE;
    }

    // glowna petla programu
    for(int ttl = 1; ttl <= MAX_TTL && !TARGET_REACHED; ttl++) {

        // kod z wykladu
        if(setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) < 0) {
            ERROR("error przy setsockopt");
        }

        // wektor na czas wyslania oraz na pakiety
        // wole wektorki
        vector<struct timeval> send_times(PACKETS_TTL);
        vector<Packet> curr_packets(PACKETS_TTL, {false, 0.0, ""});

        // to bedzie nam wyznaczalo poczatek "przedzialu" dla seq
        // dla kadzego ttl
        int seq_start = (ttl - 1) * PACKETS_TTL + 1;
 
        // wysylanie pakietow
        for(int i = 0; i < PACKETS_TTL; i++) {
            // z wykladu
            struct icmp header;
            header.icmp_type = ICMP_ECHO;
            header.icmp_code = 0;
            header.icmp_hun.ih_idseq.icd_id = htons(MY_ID); // host to network
            header.icmp_hun.ih_idseq.icd_seq = htons(SEQ);
            header.icmp_cksum = 0;
            header.icmp_cksum = compute_icmp_checksum ((u_int16_t*)&header, sizeof(header));

            // zapisujemy kiedy wysylamy pakiet
            gettimeofday(&send_times[i], NULL);

            // z wykladu 
            ssize_t bytes_sent = sendto(
                sockfd,
                &header,
                sizeof(header),
                0,
                (struct sockaddr*)&recipient,
                sizeof(recipient)
            );

            // drobny error check czy wogole zadzialalo
            if(bytes_sent < 0) {
                ERROR("error przy sendto");
            }

            SEQ++;
        }

        // no dobra to jak wyslalismy te pakiety to kiedys przydalo by sie je odebrac

        // z wykladu
        struct pollfd ps;
        ps.fd = sockfd; // deskryptor
        ps.events = POLLIN;
        ps.revents = 0;

        // powiedziane bylo w zadniu ze czekamy max sekunde wiec musimy to jakos 
        // teraz pilnowac

        int time_left = WAITING_TIME;
        while (time_left > 0) {
            struct timeval start;
            struct timeval end;
            
            gettimeofday(&start, NULL);
            // z wykladu
            int ready = poll(&ps, 1, time_left); // czeka az cos sie pojawi na gniezdzie przez max time left czasu (tablica 1 elementowa)
            gettimeofday(&end, NULL);
            
            int time_duration = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
            time_left -= time_duration;

            // zobaczmy co zwroicl poll() mamy 3 przypadki
            if (ready == 0) { // z wykladu
                break; // timeout
            } else if (ready < 0) { // z wykladu
                ERROR("poll error");
                break;
            } else { // ready > 1

                // na wykladzie bylo napisane zeby sprawdzic
                if (!(ps.revents == POLLIN)) {
                    continue;
                }

                // z wykladu
                // adres wysylajacego
                struct sockaddr_in sender;
                socklen_t sender_len = sizeof(sender);
                u_int8_t buffer[IP_MAXPACKET];
                ssize_t packet_len = recvfrom( // odbiera kolejny pakiet z kolejki zwiazanej z gniazdem
                    sockfd,
                    buffer, // pakiet jako ciag bajtow
                    IP_MAXPACKET,
                    0,
                    (struct sockaddr*)&sender, // info o
                    &sender_len                // nadawcy
                );

                // kolejny maly error check
                if(packet_len < 0) {
                    ERROR("error przy recvfrom");
                }

                // przydalo by sie wiedziec kiedy odebralismy pakiet
                struct timeval time_recive;
                gettimeofday(&time_recive, NULL);

                // odczyt naglowka ip
                struct ip* ip_header = (struct ip*) buffer;
                u_int8_t* icmp_packet = buffer + 4 * ip_header->ip_hl;
                // odczyt naglowka icmp
                struct icmp* icmp_header = (struct icmp*) icmp_packet; 

                // na wykladzie powiedziane bylo ze kod jest bez obslogi
                // wyjatkow wiec potrzebujemy je obsluzyc "logic"

                u_int16_t packet_id = 0;
                int packet_seq = 0;

                // dobra tu jednak bedzie troche wiecej zabawy niz myslalem
                // oryginalnie, dlaczego?
                // te dwie odpowiedi maja rozna struktore
                // echo ma taka sama jak oryginalnie wyslalismy
                // lecz time exceeded jest obudowany nowymi rzeczami
                // wiec aby dostac to co chcemy musimy go lekko odpakowac

                if (icmp_header->icmp_type == ICMP_ECHOREPLY) {
                    packet_id = ntohs(icmp_header->icmp_hun.ih_idseq.icd_id); // network to host
                    packet_seq = ntohs(icmp_header->icmp_hun.ih_idseq.icd_seq);
                    
                } else if (icmp_header->icmp_type == ICMP_TIME_EXCEEDED) {
                    struct ip* og_ip_header = (struct ip*)(icmp_packet + 8); // odpakowujemy oryginany pakiet
                    u_int8_t* og_icmp_packet = (icmp_packet + 8 + 4 * og_ip_header->ip_hl); // analogiczne do odczytywania naglowka wyzej
                    struct icmp* og_icmp_header = (struct icmp*) og_icmp_packet;

                    packet_id = ntohs(og_icmp_header->icmp_hun.ih_idseq.icd_id);
                    packet_seq = ntohs(og_icmp_header->icmp_hun.ih_idseq.icd_seq);
                    
                } else {
                    continue; // jakis pakiet co nas nie obchodzi
                }

                if (MY_ID == packet_id && packet_seq >= seq_start) {
                    int packet_num = packet_seq - seq_start;
                    if (!curr_packets[packet_num].received) {
                        curr_packets[packet_num].received = true;
                        curr_packets[packet_num].rtt = (time_recive.tv_sec - send_times[packet_num].tv_sec) * 1000 + (time_recive.tv_usec - send_times[packet_num].tv_usec) / 1000;
                        // z wykladu
                        char sender_ip_str[20];
                        inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));
                        curr_packets[packet_num].ip_response = sender_ip_str;
                    }
                }

            }
            int delivered = 0;
            for(int i = 0; i < PACKETS_TTL; i++) {
                if (curr_packets[i].received) {
                    delivered++;
                }
            }
            if (delivered == 3) {
                break;
            }

        }
        
        cout << ttl << ". "; // numer "hopa"

        // ok to jak juz powysylalismy i poodbieralismy to pora na zagladniecie co tam mamy
        // i wyprintowanie odpowienich rzeczy

        double total_rtt = 0.0;
        int amount = 0;
        vector<string> ip_adresses;

        for (int i = 0; i < PACKETS_TTL; i++) {
            if (curr_packets[i].received) {
                amount++;
                total_rtt += curr_packets[i].rtt;

                if (find(ip_adresses.begin(), ip_adresses.end(), curr_packets[i].ip_response) == ip_adresses.end()) {
                    ip_adresses.push_back(curr_packets[i].ip_response);
                }    
            }
        }

        if(amount == 0) {
            cout << "* \n";
        } else {
            for(size_t i = 0; i < ip_adresses.size(); i++) { // size_t bo inaczej kombilator sie denerwowal
                cout << ip_adresses[i] << " ";
            }

            if (amount == PACKETS_TTL) {
                cout << "avg: " << total_rtt / amount << "ms \n";
            } else {
                cout << "avg: ??? \n";
            }
        }

        // po tym wszystkim mozemy odpowiedziec na nurtujace nas pytanie
        // czy to nasz szukany adres jak tak to konczymy zabawe

        char target_ip_str[20];
        inet_ntop(AF_INET, &recipient.sin_addr, target_ip_str, sizeof(target_ip_str));

        for (int i = 0; i < PACKETS_TTL; i++) {
            if (curr_packets[i].ip_response == target_ip_str) {
                TARGET_REACHED = true;
                break;
            }
        }
    }
    close(sockfd);
    return EXIT_SUCCESS;
}