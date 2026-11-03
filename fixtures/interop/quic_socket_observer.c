/* Test-only Linux/glibc interposer. No socket factory, replay, queue or core flag.
 * Loaded only by the explicitly owned CLI process. Fixed cwd files select one
 * test fault; source/trace stay inside its isolated consumer guest.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif
#define MAX_LINES 16384
static int trace_fd = -1;
static char mode = 'N';
static _Atomic unsigned lines;
static _Atomic int injected;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static int (*real_socket)(int,int,int);
static int (*real_setsockopt)(int,int,int,const void*,socklen_t);
static int (*real_getsockopt)(int,int,int,void*,socklen_t*);
static int (*real_bind)(int,const struct sockaddr*,socklen_t);
static int (*real_close)(int);
static ssize_t (*real_sendmsg)(int,const struct msghdr*,int);
static ssize_t (*real_recvmsg)(int,struct msghdr*,int);
static ssize_t (*real_sendto)(int,const void*,size_t,int,const struct sockaddr*,socklen_t);
static ssize_t (*real_recvfrom)(int,void*,size_t,int,struct sockaddr*,socklen_t*);

static void initialize(void) {
#define LOAD(name) *(void **)(&real_##name) = dlsym(RTLD_NEXT, #name)
    LOAD(socket); LOAD(setsockopt); LOAD(getsockopt); LOAD(bind); LOAD(close);
    LOAD(sendmsg); LOAD(recvmsg); LOAD(sendto); LOAD(recvfrom);
#undef LOAD
    int fd = (int)syscall(SYS_openat, AT_FDCWD, "d05-control", O_RDONLY|O_CLOEXEC, 0);
    if (fd >= 0) {
        if (syscall(SYS_read, fd, &mode, 1) != 1) mode = '?';
        syscall(SYS_close, fd);
    }
    trace_fd = (int)syscall(SYS_openat, AT_FDCWD, "d05-trace.ndjson",
                          O_WRONLY|O_CREAT|O_EXCL|O_APPEND|O_CLOEXEC, 0600);
    if (trace_fd < 0 || (mode != 'N' && mode != 'F' && mode != 'C')) _exit(126);
}
static uint64_t now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec*1000000000ULL + (uint64_t)t.tv_nsec;
}
static int udp_info(int fd, uint64_t *inode, int *family, unsigned *port) {
    int type = 0; socklen_t n = sizeof(type);
    if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_TYPE, &type, &n) < 0 || type != SOCK_DGRAM)
        return 0;
    struct sockaddr_storage address; n = sizeof(address);
    if (syscall(SYS_getsockname, fd, &address, &n) < 0) return 0;
    *family = address.ss_family;
    if (*family != AF_INET && *family != AF_INET6) return 0;
    *port = *family == AF_INET ? ntohs(((struct sockaddr_in*)&address)->sin_port)
                              : ntohs(((struct sockaddr_in6*)&address)->sin6_port);
    struct stat s;
    if (fstat(fd, &s) < 0) return 0;
    *inode = s.st_ino;
    return 1;
}
static void record(int fd, const char *op, int level, int option, int value,
                   long result, int err, int segment, int ecn, size_t bytes,
                   unsigned peer_port, const char *hashes, int forced) {
    int saved = errno, family; unsigned port; uint64_t inode;
    int mark=0; socklen_t mark_length=sizeof(mark);
    if (syscall(SYS_getsockopt,fd,SOL_SOCKET,SO_MARK,&mark,&mark_length)!=0) mark=-1;
    if (fd == trace_fd || !udp_info(fd, &inode, &family, &port)) { errno=saved; return; }
    unsigned seq = atomic_fetch_add(&lines, 1);
    if (seq > MAX_LINES) { errno=saved; return; }
    char line[1024];
    int n;
    if (seq == MAX_LINES) n=snprintf(line,sizeof(line),"{\"op\":\"overflow\"}\n");
    else n=snprintf(line,sizeof(line),
        "{\"op\":\"%s\",\"seq\":%u,\"ns\":%llu,\"fd\":%d,\"inode\":%llu,"
        "\"family\":%d,\"mark\":%d,\"local_port\":%u,\"peer_port\":%u,\"level\":%d,"
        "\"option\":%d,\"value\":%d,\"result\":%ld,\"errno\":%d,"
        "\"gso\":%d,\"ecn\":%d,\"bytes\":%zu,\"forced\":%d,\"hashes\":[%s]}\n",
        op,seq,(unsigned long long)now_ns(),fd,(unsigned long long)inode,family,mark,port,
        peer_port,level,option,value,result,err,segment,ecn,bytes,forced,hashes?hashes:"");
    if (n > 0 && (size_t)n < sizeof(line)) {
        if (syscall(SYS_write, trace_fd, line, (size_t)n) != n) _exit(126);
    } else _exit(126);
    errno=saved;
}
static unsigned destination_port(const struct sockaddr *address, socklen_t size) {
    if (!address) return 0;
    if (address->sa_family == AF_INET && size >= sizeof(struct sockaddr_in))
        return ntohs(((const struct sockaddr_in*)address)->sin_port);
    if (address->sa_family == AF_INET6 && size >= sizeof(struct sockaddr_in6))
        return ntohs(((const struct sockaddr_in6*)address)->sin6_port);
    return 0;
}
static void ancillary(const struct msghdr *message, int *gso, int *ecn) {
    *gso=0; *ecn=-1;
    for (struct cmsghdr *c=CMSG_FIRSTHDR(message); c; c=CMSG_NXTHDR((struct msghdr*)message,c)) {
        if (c->cmsg_level == SOL_UDP && c->cmsg_type == UDP_SEGMENT && c->cmsg_len >= CMSG_LEN(2)) {
            uint16_t v; memcpy(&v,CMSG_DATA(c),2); *gso=v;
        }
        if ((c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_TOS)
            || (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_TCLASS)) {
            if (c->cmsg_len >= CMSG_LEN(1)) *ecn=*(unsigned char*)CMSG_DATA(c)&3;
        }
    }
}
static size_t content_hashes(const struct msghdr *message, int gso, char out[256]) {
    size_t length=0;
    for (size_t i=0;i<message->msg_iovlen;i++) length += message->msg_iov[i].iov_len;
    out[0]=0;
    /* The candidate supplies one borrowed iovec; a wider shape is diagnostic FAIL. */
    if (message->msg_iovlen != 1 || !gso || length > 65507 || (length+gso-1)/(size_t)gso > 10)
        return length;
    const unsigned char *p=message->msg_iov[0].iov_base;
    size_t used=0;
    for (size_t offset=0;offset<length;offset+=(size_t)gso) {
        size_t take=length-offset; if (take>(size_t)gso) take=(size_t)gso;
        uint64_t h=14695981039346656037ULL;
        for (size_t j=0;j<take;j++) { h^=p[offset+j]; h*=1099511628211ULL; }
        int n=snprintf(out+used,256-used,"%s\"%016llx\"",used?",":"",(unsigned long long)h);
        if (n<0 || (size_t)n>=256-used) _exit(126);
        used+=(size_t)n;
    }
    return length;
}
int socket(int domain,int type,int protocol) {
    pthread_once(&once,initialize);
    int result=real_socket(domain,type,protocol), err=errno;
    if (result>=0) record(result,"socket",0,0,protocol,result,0,0,-1,0,0,NULL,0);
    errno=err; return result;
}
int setsockopt(int fd,int level,int option,const void *p,socklen_t len) {
    pthread_once(&once,initialize);
    int value=0, forced=0;
    if (len>=sizeof(int)) memcpy(&value,p,sizeof(value));
    int expected=0;
    if (mode=='C' && ((level==IPPROTO_IP&&option==IP_RECVTOS)
                   ||(level==IPPROTO_IPV6&&option==IPV6_RECVTCLASS))
        && atomic_compare_exchange_strong(&injected,&expected,1)) forced=1;
    int result;
    if (forced) { errno=ENOPROTOOPT; result=-1; }
    else result=real_setsockopt(fd,level,option,p,len);
    int err=result<0?errno:0;
    /* Every record reads SO_MARK from this same fd; no probe socket. */
    record(fd,"setsockopt",level,option,value,result,err,0,-1,0,0,NULL,forced);
    errno=err; return result;
}
int getsockopt(int fd,int level,int option,void *p,socklen_t *len) {
    pthread_once(&once,initialize);
    int result=real_getsockopt(fd,level,option,p,len),err=result<0?errno:0,value=0;
    if (!result && *len>=sizeof(int)) memcpy(&value,p,sizeof(value));
    if (level==SOL_UDP && option==UDP_GRO)
        record(fd,"getsockopt",level,option,value,result,err,0,-1,0,0,NULL,0);
    errno=err; return result;
}
int bind(int fd,const struct sockaddr *address,socklen_t size) {
    pthread_once(&once,initialize);
    int result=real_bind(fd,address,size),err=result<0?errno:0;
    record(fd,"bind",0,0,0,result,err,0,-1,0,0,NULL,0);
    errno=err; return result;
}
ssize_t sendmsg(int fd,const struct msghdr *message,int flags) {
    pthread_once(&once,initialize);
    int gso,ecn; ancillary(message,&gso,&ecn);
    char hashes[256]; size_t bytes=content_hashes(message,gso,hashes);
    int expected=0,forced=mode=='F'&&gso&&ecn<0
        && atomic_compare_exchange_strong(&injected,&expected,1);
    ssize_t result;
    if (forced) { errno=ENOPROTOOPT; result=-1; } /* Never enter kernel; never replay. */
    else result=real_sendmsg(fd,message,flags);
    int err=result<0?errno:0;
    record(fd,"sendmsg",0,0,flags,result,err,gso,ecn,bytes,
           destination_port(message->msg_name,message->msg_namelen),hashes,forced);
    errno=err; return result;
}
ssize_t recvmsg(int fd,struct msghdr *message,int flags) {
    pthread_once(&once,initialize);
    ssize_t result=real_recvmsg(fd,message,flags); int err=result<0?errno:0;
    int gso=0,ecn=-1; if (result>=0) ancillary(message,&gso,&ecn);
    if (result>=0 || err!=EAGAIN)
        record(fd,"recvmsg",0,0,message->msg_flags,result,err,gso,ecn,
               result>0?(size_t)result:0,destination_port(message->msg_name,message->msg_namelen),NULL,0);
    errno=err; return result;
}
ssize_t sendto(int fd,const void *p,size_t size,int flags,const struct sockaddr *a,socklen_t n) {
    pthread_once(&once,initialize);
    ssize_t result=real_sendto(fd,p,size,flags,a,n); int err=result<0?errno:0;
    record(fd,"sendto",0,0,flags,result,err,0,-1,size,destination_port(a,n),NULL,0);
    errno=err; return result;
}
ssize_t recvfrom(int fd,void *p,size_t size,int flags,struct sockaddr *a,socklen_t *n) {
    pthread_once(&once,initialize);
    ssize_t result=real_recvfrom(fd,p,size,flags,a,n); int err=result<0?errno:0;
    if (result>=0 || err!=EAGAIN)
        record(fd,"recvfrom",0,0,flags,result,err,0,-1,result>0?(size_t)result:0,
               destination_port(a,n?*n:0),NULL,0);
    errno=err; return result;
}
int close(int fd) {
    pthread_once(&once,initialize);
    record(fd,"close",0,0,0,0,0,0,-1,0,0,NULL,0);
    return real_close(fd);
}
