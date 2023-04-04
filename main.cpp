#include <iostream>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <cstring>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <cstring>
#include <netinet/in_systm.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
using namespace std;
class tcphdr_chksum{
public:
    in_addr_t src;
    in_addr_t dst;
    char proto;
    short tcplen;
};
short chksum(tcphdr_chksum& h,int l){
    short* p = (short*)&h;
    long sum=0;
    unsigned short odd;
    int remain = l;
    short r;
    while(remain > 1){
        sum += *p++;
        remain-=2;
    }
    if(remain==1){
        *((u_char*)&odd) = *(u_char*)p;
        sum += odd;
    }
    sum = (sum>>16)+(sum&0xffff);
    sum = sum+(sum>>16);
    r = (short)~sum;
    return r;
}

int main(){
    int s = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
    if(s<0){
        cout<<"socket err"<<endl;
        return -1;
    }
    char SendBuf[256];
    tcphdr* hdr = (tcphdr*)SendBuf;
    memset(hdr,0,sizeof(tcphdr));
    hdr->source = htons(1234);//source port
    hdr->dest = htons(4321);
    hdr->th_flags |= TH_SYN;
    hdr->th_seq = 7;
    hdr->syn = 1;
    hdr->window = htons(128);
    hdr->doff = 12;
    hdr->th_win = htons(5840);
    hdr->th_dport = htons(1234);
    hdr->th_sport = htons(4321);
    int* mss = (int*)(SendBuf+sizeof(tcphdr));
    *mss = htonl(0x020405b4);

    tcphdr_chksum chk;
    chk.src = inet_addr("192.168.177.118");
    chk.dst = inet_addr("192.168.177.248");
    chk.proto = IPPROTO_TCP;
    chk.tcplen = sizeof(tcphdr);
    hdr->check = chksum(chk,sizeof(chk));

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("192.168.177.248");
    int bytes = sendto(s,SendBuf,sizeof(tcphdr)+sizeof(*mss),0,(sockaddr*)&addr,
                       sizeof(addr));
    cout<<errno<<":"<<gai_strerror(errno)<<endl;
    cout<<bytes<<endl;
    char c;
    cin>>c;
    return 0;
}
