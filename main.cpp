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
int s;
class interface{
public:
    string name;
    sockaddr* addr;
    sockaddr* subnet;
    sockaddr* netID;
    void makeNetID(){
        this->netID = new sockaddr;
        ((sockaddr_in*)this->netID)->sin_addr.s_addr =
                ((sockaddr_in*)addr)->sin_addr.s_addr
                &
                ((sockaddr_in*)subnet)->sin_addr.s_addr;
    }
};
#define MAX_IFS 10
class HostV4{
public:
    in_addr_t addr;
    bool isUp;
};
#define HOSTS_MAX (256*128)
bool is_NetID(interface& iff,sockaddr* addr){
    in_addr_t netmask=((sockaddr_in*)iff.subnet)->sin_addr.s_addr,
            ad=((sockaddr_in*)addr)->sin_addr.s_addr;
    netmask = ntohl(netmask);
    ad = ntohl(ad);
    if(((~netmask) & ad) == 0)
        return true;
    return false;
}
bool is_BroadCast(interface& iff,sockaddr* addr){
    in_addr_t netmask=((sockaddr_in*)iff.subnet)->sin_addr.s_addr,
            ad=((sockaddr_in*)addr)->sin_addr.s_addr;
    if((int)(netmask | ad)==-1)
        return true;
    return false;
}
bool is_Host(interface& iff,sockaddr* addr){
    if(!is_NetID(iff,addr) && !is_BroadCast(iff,addr))
        return true;
    return false;
}
class host{
public:
    sockaddr* addr;
    bool isUp;
};
bool netIDContains(interface& iff,in_addr_t addr){
    sockaddr_in r;
    r.sin_family = iff.netID->sa_family;
    in_addr_t netmask = ((sockaddr_in*)iff.subnet)->sin_addr.s_addr;
    in_addr_t netid = ((sockaddr_in*)iff.netID)->sin_addr.s_addr;
    if((addr&netid) == netid)
        return true;
    return false;
}
int icmp_cksum(icmp* h,int l);
uint16_t ICMPChecksum(uint16_t *icmph, int len);
int main(){
    s = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    setuid(getuid());
    interface ifs[10]={{"",nullptr,nullptr,nullptr}};
    int index=0;
    bool flag;
    ifaddrs* interfaces;
    getifaddrs(&interfaces);
    for(ifaddrs* i = interfaces;i;i=i->ifa_next){
        flag = false;
        for(int j=0;j<index;j++){
            if(i->ifa_name == ifs[j].name)
                flag = true;
        }
        if(flag || i->ifa_addr->sa_family != AF_INET)
            continue;
        ifs[index].addr = i->ifa_addr;
        ifs[index].subnet = i->ifa_netmask;
        ifs[index].name = i->ifa_name;
        ifs[index].makeNetID();
        index++;
    }
    cout<<"interfaces : "<<endl;
    for(int i=0;i<index;i++){
        cout<<i<<" - "<<ifs[i].name<<endl;
    }
    int choose;
    cout<<"Enter interface index to check hosts : ";cin>>choose;
    in_addr i;
    i.s_addr = ((sockaddr_in*)ifs[choose].netID)->sin_addr.s_addr;
    sockaddr_in p;
    p.sin_family = AF_INET;
    HostV4 hosts[HOSTS_MAX]={{0,false}};
    int host_index=0;
    int recvbufsize = 1024*10;
    if(setsockopt(s,SOL_SOCKET,SO_RCVBUF,&recvbufsize,sizeof(recvbufsize))){
        cout<<"setsockopt err"<<endl;
        return -1;
    }
    char sendBuf[1024]={0};
    icmp* icmph = (icmp*)sendBuf;
    int icd_seq=0,pid = getpid();
    cout<<"hosts : "<<endl;
    while(netIDContains(ifs[choose],i.s_addr)){
        p.sin_addr = i;
        i.s_addr = ntohl(i.s_addr);
        i.s_addr++;
        i.s_addr = htonl(i.s_addr);
        if(is_NetID(ifs[choose],(sockaddr*)&p))
            continue;
        if(is_BroadCast(ifs[choose],(sockaddr*)&p))
            continue;
        cout<<inet_ntoa(p.sin_addr)<<endl;
        if(index < HOSTS_MAX)
            hosts[host_index++].addr = p.sin_addr.s_addr;
        memset(icmph,0,sizeof(icmp));
        icmph->icmp_code = 0;
        icmph->icmp_type = ICMP_ECHO;
        icmph->icmp_hun.ih_idseq.icd_seq = icd_seq++;
        icmph->icmp_hun.ih_idseq.icd_id = pid;
        gettimeofday((timeval*)icmph->icmp_dun.id_data,nullptr);
        if(p.sin_addr.s_addr == inet_addr("192.168.177.248"))
            cout<<"br"<<endl;
        icmph->icmp_cksum = icmp_cksum(icmph,56+8);
        int bytes = sendto(s,sendBuf,56+8,0,(sockaddr*)&p,sizeof(p));
    }
    cout<<"up hosts : "<<endl;
    int bytes;
    sockaddr_in from;
    socklen_t l = sizeof(from);
    char RecvBuf[128];
    while(true){
        bytes=recvfrom(s,RecvBuf,128,0,(sockaddr*)&from,&l);
        ip* iph = (ip*)RecvBuf;
        icmp* ih = (icmp*)(RecvBuf+sizeof(*iph));
        if(ih->icmp_type == ICMP_ECHOREPLY)
            cout<<"reply from "<<inet_ntoa(iph->ip_src)<<endl;
    }
    return 0;
}
int icmp_cksum(icmp* h,int l){
    unsigned short* p = (unsigned short*)h;
    int sum=0,remain=l;
    unsigned short r;
    while(remain > 1){
        sum += *p++;
        remain -= 2;
    }
    if(remain == 1){
        *(unsigned char*)(&r) = *(unsigned char*)p;
        sum += r;
    }
    sum = (sum>>16)+(sum&0xffff);
    sum += (sum>>16);
    r = ~sum;
    return r;
}
