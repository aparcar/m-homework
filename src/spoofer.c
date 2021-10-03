#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

/*
 * DNS structure as described in the CS4700/CS5700 document here:
 * https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
 */

#define T_A 0x100 // 1: IPv4 address
#define BUFSIZE 65536
#define SPOOF_IP "6.6.6.6" // hard coded spoof address

/**
 * Structure that is mapped to the begin of a DNS packet
 */
struct DNS_header {
  int16_t id;
  uint8_t qr : 1;
  uint8_t opcode : 4;
  uint8_t aa : 1;
  uint8_t tc : 1;
  uint8_t rd : 1;
  uint8_t ra : 1;
  uint8_t z : 3;
  uint8_t rcode : 4;
  uint16_t qdcount; // (16bit) question count
  uint16_t ancount; // (16bit) answer count
  uint16_t nscount; // (16bit) name server count
  uint16_t arcount; // (16bit) ressource count
};

/**
 * Structure that is mapped after the incomming question (qname)
 */
struct DNS_question_data {
  uint16_t qtype;
  uint16_t qclass;
};

/**
 * Structure that is attached to the response containing the answer
 */
struct DNS_answers_data {
  uint16_t qtype;
  uint16_t qclass;
  uint32_t ttl;
  uint16_t rdlength;
};

/**
 * Decode a DNS package and attach found answers if available
 *
 * @param buffer containing the request and in case of successfull resolving
 * the answer
 * @param bufsize contains the length of the buffer
 * @return length of modified buffer containing the response or zero if
 * request wasn't valid (aka no A record request)
 */
int process_dns_packet(char *buffer, uint16_t bufsize) {
  uint8_t qname_length = 1, rdlength = 4; // IPv4 addresses take 4 Byte

  // map DNS_header struct to start of DNS packet
  struct DNS_header *header = (struct DNS_header *)buffer;
  buffer += sizeof(struct DNS_header);

  // after the header comes the qname aka requested domain, spoofer don't
  // carsed about it so just skip the buffer to the end of it
  // the trailing 0 of qname is considered part of it, so add + 1
  qname_length = strlen(buffer) + 1;
  buffer += qname_length;

  // map DNS_question_data behind the qname
  struct DNS_question_data *question_data =
      (struct DNS_question_data *)(buffer);
  buffer += sizeof(struct DNS_question_data);

  // check if actually A record requested, AAAA, MX etc is not supported
  if (question_data->qtype != T_A) {
    fprintf(stderr, "spoofer only supports QTYPE A (1). Got %d\n",
            ntohs(question_data->qtype));
    return 0;
  }

  // modify header bits to turn into a response as described in the CS document
  header->ancount = htons(1);
  header->arcount = htons(0);
  header->qr = 1;
  header->ra = 1;
  header->rd = 1;

  // use DNS compression pointing statically to the question just after
  // header. This is a simplifcation of the actual standard as this way only
  // a single hostname question is supported per request
  *buffer++ = 0xc0;
  *buffer++ = 0x0c;

  // map the DNS_answe_data behind DNS answer pointer
  struct DNS_answers_data *answer_data = (struct DNS_answers_data *)(buffer);
  // ideally the struct is 10 Byte but due do compiler optimization it becomes
  // 12 on x86 systems. Manually distract two bytes here
  buffer += sizeof(struct DNS_answers_data) - 2; // strange

  // set answer data based on CS document
  answer_data->qtype = question_data->qtype; // respond with A recond
  answer_data->qclass = htons(1);
  // set ttl to 600 seconds
  answer_data->ttl = htonl(0x258);

  // use inet_pton to decode IP address string to buffer
  puts("IPv4 address requested");
  inet_pton(AF_INET, SPOOF_IP, buffer);
  answer_data->rdlength = htons(rdlength);

  // returns the final packet length
  return sizeof(struct DNS_header) + qname_length +
         sizeof(struct DNS_question_data) + rdlength +
         sizeof(struct DNS_answers_data);
}

int main(uint8_t argc, char **argv) {
  unsigned int len, n, port;
  int sockfd;
  char buffer[BUFSIZE];
  struct sockaddr_in servaddr, cliaddr;

  // Run tool on a specific port since 53 requires root
  if (argc < 2) {
    fprintf(stderr, "Usage: %s port\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  // load port number
  if ((port = atoi(argv[1])) == 0) {
    fprintf(stderr, "please choose a valid port as first argument\n");
    exit(1);
  }

  fprintf(stderr, "Spoofer listening on port %d\n", port);

  /*
   * socket code adopted from geeksforgeeks.org
   * https://www.geeksforgeeks.org/udp-server-client-implementation-c/
   */

  // create a socket 
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  memset(&servaddr, 0, sizeof(servaddr));
  memset(&cliaddr, 0, sizeof(cliaddr));

  servaddr.sin_family = AF_INET; // IPv4
  servaddr.sin_addr.s_addr = inet_addr("127.0.0.1"); // local only
  servaddr.sin_port = htons(port);

  if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  len = sizeof(cliaddr);

  // serve forever
  while (1) {
    n = recvfrom(sockfd, (char *)buffer, BUFSIZE, MSG_WAITALL,
                 (struct sockaddr *)&cliaddr, &len);

    // ignore empty incomming packages
    if (n == 0)
      continue;

    // resolve the request
    n = process_dns_packet(buffer, n);

    // only respond if a A record was requested
    if (n > 0) {
      sendto(sockfd, (const char *)buffer, n, MSG_CONFIRM,
             (const struct sockaddr *)&cliaddr, len);
    }
  }

  return 0;
}
