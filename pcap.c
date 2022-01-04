#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<time.h>

#define BUFSIZE 10240
#define STRSIZE 1024

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;
typedef u_int16_t  u_short;
typedef u_int32_t u_int32;
typedef u_int16_t u_int16;
typedef u_int8_t u_int8;

struct pcap_file_header
{
    bpf_u_int32 magic;
    u_short version_major;
    u_short version_minor;
    bpf_int32 thiszone;
    bpf_u_int32 sigfigs;
    bpf_u_int32 snaplen;
    bpf_u_int32 linktype;
};

struct time_val
{
    int tv_sec;
    int tv_usec;
};

struct pcap_pkthdr
{
    struct time_val ts;
    bpf_u_int32 caplen;
    bpf_u_int32 len;
};


typedef struct FramHeader_t
{
    u_int8 DstMAC[6];
    u_int8 SrcMAC[6];
    u_short FrameType;
} FramHeader_t;

typedef struct IPHeader_t
{
    u_int8 Ver_HLen;
    u_int8 TOS;
    u_int16 TotalLen;
    u_int16 ID;
    u_int16 Flag_Segment;
    u_int8 TTL;
    u_int8 Protocol;
    u_int16 Checksum;
    u_int32 SrcIP;
    u_int32 DstIP;
} IPHeader_t;


typedef struct TCPHeader_t
{
    u_int16 SrcPort;
    u_int16 DstPort;
    u_int32 SeqNO;
    u_int32 AckNO;
    u_int8 HeaderLen;
    u_int8 Flags;
    u_int16 Window;
    u_int16 Checksum;
    u_int16 UrgentPointer;
}TCPHeader_t;

typedef struct UDPHeader_s
{
    u_int16_t SrcPort;
    u_int16_t DstPort;
    u_int16_t len;
    u_int16_t checkSum;
}UDPHeader_t;

int main(int argc, char *argv[])
{
    struct pcap_file_header *file_header;
    struct pcap_pkthdr *ptk_header;
    FramHeader_t *mac_header;
    IPHeader_t *ip_header;
    TCPHeader_t *tcp_header;
    UDPHeader_t *udp_header;

    FILE *fp, *output;
    int   pkt_offset, i = 0;
    int ip_len, http_len, ip_proto;
    int src_port, dst_port;

    char buf[BUFSIZE], my_time[STRSIZE];
    char src_ip[STRSIZE], dst_ip[STRSIZE];

    ptk_header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
    mac_header = (FramHeader_t *)malloc(sizeof(FramHeader_t));
    ip_header = (IPHeader_t *)malloc(sizeof(IPHeader_t));
    tcp_header = (TCPHeader_t *)malloc(sizeof(TCPHeader_t));
    udp_header = (UDPHeader_t *)malloc(sizeof(UDPHeader_t));

    if(argc > 2)
    {
      printf("error\n");
      exit(0);
    }
    char FILE_NAME[STRSIZE];
    printf("\n%s\n", argv[1]);
    memcpy(FILE_NAME, argv[1], strlen(argv[1]));
    printf("file name: %s\n", FILE_NAME);
    if ((fp = fopen(FILE_NAME, "r")) == NULL)
    {
        printf("error: can not open pcap file\n");
        exit(0);
    }
    pkt_offset = 24;

    while (fseek(fp, pkt_offset, SEEK_SET) == 0)
    {
        i++;
        //pcap_pkt_header 16 byte
        memset(ptk_header, 0, sizeof(struct pcap_pkthdr));
        if (fread(ptk_header, 16, 1, fp) != 1)
        {
            printf("\nEnd of pcap file\n");
            break;
        }

        pkt_offset += 16 + ptk_header->caplen;

        struct tm *timeinfo;
        time_t t = (time_t)(ptk_header->ts.tv_sec);
        timeinfo = localtime(&t);

        strftime(my_time, sizeof(my_time), "%Y-%m-%d %H:%M:%S", timeinfo);
        //printf("%s\n", my_time);

        //fseek(fp, 14, SEEK_CUR);
        memset(mac_header, 0, sizeof(struct FramHeader_t));

        printf("time:%s\n",my_time);

        if(fread(mac_header, 14, 1, fp)!= 1)
        {
          printf("%d: can not read mac_header\n", i);
          break;
        }

        int j = 0;
        printf("mac Src:");
        for(j = 0; j<6; j++)
        {
          if(mac_header->SrcMAC[j] == 0x00)
            printf("0");
          printf("%x", mac_header->SrcMAC[j]);
          if(j!=5)
            printf(":");
        }
        printf(" ,mac Dst:");
        for(j = 0; j<6; j++)
        {
          if(mac_header->DstMAC[j] == 0x00)
            printf("0");
          printf("%x", mac_header->DstMAC[j]);
          if(j!=5)
            printf(":");
        }
        printf(" Type:0x%x", htons(mac_header->FrameType));
        if(mac_header->FrameType == ntohs(0x0800))
          printf("(IPv4)");
        printf("\n");

        //ip
        memset(ip_header, 0, sizeof(IPHeader_t));
        if (fread(ip_header, sizeof(IPHeader_t), 1, fp) != 1)
        {
            printf("%d: can not read ip_header\n", i);
            break;
        }
        inet_ntop(AF_INET, (void *)&(ip_header->SrcIP), src_ip, 16);
        inet_ntop(AF_INET, (void *)&(ip_header->DstIP), dst_ip, 16);
        printf("src_ip:%s, dst_ip:%s\n", src_ip, dst_ip);

        //tcp udp
        if(ip_header->Protocol == 0x06)
        {
          printf("Protocol:0x06(TCP)\n");
          if(fread(tcp_header, sizeof(TCPHeader_t), 1, fp) != 1)
          {
              printf("%d: can not read tcp_header\n", i);
              break;
          }
          printf("src_port:%d, dst_port:%d\n", htons(tcp_header->SrcPort), htons(tcp_header->DstPort));
        }
        else if(ip_header->Protocol == 0x11)
        {
          printf("Protocol:0x11(UDP)\n");
          if(fread(udp_header, sizeof(UDPHeader_t), 1, fp) != 1)
          {
              printf("%d: can not read tcp_header\n", i);
              break;
          }
          printf("src_port:%d, dst_port:%d\n", htons(udp_header->SrcPort), htons(udp_header->DstPort));
        }
        else
          printf("Protocol:0x%x\n", ip_header->Protocol);
        printf("\n");
    } // end while
    fclose(fp);
    free(ptk_header);
    free(ip_header);
    free(tcp_header);
    return 0;
}
