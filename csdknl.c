#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>
#include <android/log.h>
#include "com_android_server_mia_Interface.h"
#include "csdkdef.h"

#define CLOSE_JNI_LOG

#ifdef CLOSE_JNI_LOG
#define __android_log_print(...)
#endif

#define NETLINK_TEST   29
#define TAG            "CSDK_NL"

#define SOCKET_CREATE_ERROR -1
#define SOCKET_BIND_ERROR -2
#define SOCKET_SEND_ERROR -3
#define SOCKET_MALLOC_ERROR -4
 
int netlink_sendmsg(int ctrl_type, void *pData, int nlen)
{
        int sock_status = 0;
        int sock_fd;

        sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_TEST);
        if(sock_fd == -1) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "create socket error!");
            return SOCKET_CREATE_ERROR;
        }

        struct sockaddr_nl src_addr;
        memset(&src_addr, 0, sizeof(struct sockaddr_nl));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = getpid();
        src_addr.nl_groups = 0;

        sock_status = bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(struct sockaddr_nl));
        if (sock_status < 0){
            __android_log_print(ANDROID_LOG_ERROR, TAG, "bind socket error!!");
            close(sock_fd);
            return SOCKET_BIND_ERROR;
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(nlen));
        if(!nlh) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, " nlh malloc error!");
            return SOCKET_MALLOC_ERROR;
        }
        nlh->nlmsg_len = NLMSG_SPACE(nlen);
        nlh->nlmsg_pid = getpid();
        nlh->nlmsg_type = ctrl_type;
        nlh->nlmsg_flags = 0;

        memcpy(NLMSG_DATA(nlh), pData, nlen);

        struct iovec iov;
        iov.iov_base = (void *)nlh;
        iov.iov_len = nlh->nlmsg_len;

        struct sockaddr_nl dest_addr;
        memset(&dest_addr, 0, sizeof(struct sockaddr_nl));
        dest_addr.nl_family = AF_NETLINK;
        dest_addr.nl_pid = 0;
        dest_addr.nl_groups = 0;

        struct msghdr msg;
        memset(&msg, 0, sizeof(struct msghdr));
        msg.msg_name = (void *)&dest_addr;
        msg.msg_namelen = sizeof(struct sockaddr_nl);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        sock_status = sendmsg(sock_fd, &msg, 0);
        if (sock_status < 0){
            __android_log_print(ANDROID_LOG_ERROR, TAG, " send socket error!");
            sock_status = SOCKET_SEND_ERROR;
        }

        free(nlh);
        close(sock_fd);
        return sock_status;
}
int String2FilterPort(const char* sStr, int bBL, SFilterPort *pFilterPort)
{
    int bRet = 0;
    const char *p = sStr;
    SPort Port;
    int bPhase2 = 0;

    if (bBL){
        pFilterPort->blCnt = 0;
    } else {
        pFilterPort->wlCnt = 0;
    }
    Port.Begin = 0;
    Port.End = 0;
    while (1)
    {
        switch (*p)
        {
            case ',':
            case 0:
                if (Port.Begin != 0)
                {
                    if (!bPhase2)
                    {
                        Port.End = Port.Begin;
                    }
                    if (bBL)
                    {
                        if (pFilterPort->blCnt >= MAX_ITEM_COUNT)
                        {
                            return 1;
                        }
                        memcpy(&pFilterPort->BL[pFilterPort->blCnt], &Port, sizeof(Port));
                        pFilterPort->blCnt ++;
                    }
                    else
                    {
                        if (pFilterPort->wlCnt >= MAX_ITEM_COUNT)
                        {
                            return 1;
                        }
                        memcpy(&pFilterPort->WL[pFilterPort->wlCnt], &Port, sizeof(Port));
                        pFilterPort->wlCnt ++;
                    }
                    Port.Begin = 0;
                    Port.End = 0;
                    bRet = 1;
                    bPhase2 = 0;
                }
                break;
            case '-':
                bPhase2 = 1;
                break;
            default:
                if (bPhase2)
                {
                    Port.End = (Port.End * 10) + (*p - 0x30);
                }
                else
                {
                    Port.Begin = (Port.Begin * 10) + (*p - 0x30);
                }
                break;
        }
        if (*p)
        {
            p ++;
        }
        else
        {
            break;
        }
    }
    return bRet;
}

JNIEXPORT jboolean JNICALL Java_com_android_server_mia_Interface_Init
  (JNIEnv *env, jclass cls, jint uid)
{
    __android_log_print(ANDROID_LOG_ERROR, TAG, " Interface_Init ...");
    return (netlink_sendmsg(PACKFILTER_IOCTL_SET_REINIT, "init", strlen("init")+1) >= 0);
}
JNIEXPORT jboolean JNICALL Java_com_android_server_mia_Interface_Release
  (JNIEnv *env, jclass cls){
    __android_log_print(ANDROID_LOG_ERROR, TAG, " Interface_Release ...");
    return 1;
}
JNIEXPORT jboolean JNICALL Java_com_android_server_mia_Interface_ClearUids
  (JNIEnv *env, jclass cls)
{
    __android_log_print(ANDROID_LOG_ERROR, TAG, " Interface_ClearUids ...");
    return (netlink_sendmsg(PACKFILTER_IOCTL_SET_CLRUID, "clearuid", strlen("clearuid")+1) >= 0);
}
JNIEXPORT jboolean JNICALL Java_com_android_server_mia_Interface_ClearIpHosts
  (JNIEnv *env, jclass cls)
{
    __android_log_print(ANDROID_LOG_ERROR, TAG, " Interface_ClearIpHosts ...");
    return (netlink_sendmsg(PACKFILTER_IOCTL_SET_CLRIPHOST, "cleariphosts", strlen("cleariphosts")+1) >= 0);
}
JNIEXPORT jboolean JNICALL Java_com_android_server_mia_Interface_SetDefaultLimited
  (JNIEnv *env, jclass cls, jint nLimited)
{
    __android_log_print(ANDROID_LOG_ERROR, TAG, " Interface_SetDefaultLimited ...");
    return (netlink_sendmsg(PACKFILTER_IOCTL_SET_ENABLED, &nLimited, sizeof(int)) >= 0);
}
JNIEXPORT jboolean JNICALL Java_com_android_server_mia_Interface_Enable
  (JNIEnv *env, jclass cls, jint nEnable)
{
    __android_log_print(ANDROID_LOG_ERROR, TAG, " Interface_Enable ...");
    return (netlink_sendmsg(PACKFILTER_IOCTL_SET_ENABLED, &nEnable, sizeof(int)) >= 0);
}
JNIEXPORT jboolean JNICALL Java_com_android_server_mia_Interface_SetNetFilterRule
        (JNIEnv *env, jclass cls, jint type, jstring ip_url, jint ipdelta_uid, jint limited)
{
    __android_log_print(ANDROID_LOG_ERROR, TAG, " SetNetFilterRule ...");
    const char *szIP_URL = (*env)->GetStringUTFChars(env, ip_url, NULL);
    int nl_status = 0;
    switch (type)
    {
        case CR_LIMITED_APP:
        {
            SUidNode *pNodeTmp = malloc(sizeof(SUidNode));
            if(!pNodeTmp) {
                __android_log_print(ANDROID_LOG_ERROR, TAG, " pNodeTmp malloc error!");
                return 0;
            }
            memset(pNodeTmp, 0, sizeof(SUidNode));
            pNodeTmp->FlagFilter = limited;
            pNodeTmp->uUid = ipdelta_uid;
            nl_status = (netlink_sendmsg(PACKFILTER_IOCTL_SET_FILTERUID, pNodeTmp, sizeof(SUidNode)) >= 0);
            free(pNodeTmp);
        }
            break;
        case CR_LIMITED_WEB:
        {
            SFilterHost *pNodeTmp = malloc(sizeof(SFilterHost));
            if (!pNodeTmp) {
                __android_log_print(ANDROID_LOG_ERROR, TAG, " pNodeTmp malloc error!");
                return 0;
            }
            memset(pNodeTmp, 0, sizeof(SFilterHost));
            if (szIP_URL)
            {
                pNodeTmp->FlagFilter = limited;
                __android_log_print(ANDROID_LOG_ERROR, TAG, "SetNetFilterRule szIP_URL = %s, FlagFilter=%d", szIP_URL, pNodeTmp->FlagFilter);

                char *p_Temp = NULL;
                char *p_outer = NULL;
                // *.sohu.com:1,2,5-7,9,31
                p_Temp = strtok_r(szIP_URL, ":", &p_outer); // for Host strtok_r
                pNodeTmp->Host.nLen = strlen(p_Temp);
                memcpy(pNodeTmp->Host.sName, p_Temp, pNodeTmp->Host.nLen + 1);

                __android_log_print(ANDROID_LOG_ERROR, TAG, "SetNetFilterRule p_Temp1 = %s", p_Temp);
                p_Temp = strtok_r(NULL, ":", &p_outer); // for Ports strtok_r

                if (p_Temp !=NULL ){
                    __android_log_print(ANDROID_LOG_ERROR, TAG, "SetNetFilterRule p_Temp2 = %s!", p_Temp);
                    String2FilterPort(p_Temp, pNodeTmp->FlagFilter == FLAG_FILTER_BLACK? 1:0,  &pNodeTmp->FilterPort);
                }

                nl_status = (
                        netlink_sendmsg(PACKFILTER_IOCTL_SET_FILTERHOST, pNodeTmp, sizeof(SFilterHost)) >= 0);
            }
            free(pNodeTmp);
        }
            break;
        case CR_LIMITED_IP:
        {
            SFilterIp *pNodeTmp = malloc(sizeof(SFilterIp));
            if (!pNodeTmp) {
                __android_log_print(ANDROID_LOG_ERROR, TAG, "pNodeTmp malloc error!");
                return 0;
            }
            memset(pNodeTmp, 0, sizeof(SFilterIp));
            if (szIP_URL) {
                char *p_Temp = NULL;
                char *p_strtok = NULL;

                pNodeTmp->FlagFilter = limited;
                //223.110.2.12/24:1,2,5-7,80,443
                p_Temp = strtok_r(szIP_URL, ":", &p_strtok); // for Host strtok_r
                pNodeTmp->IpBegin.uIpV4 = atoi(p_Temp);
                pNodeTmp->IpEnd.uIpV4 = pNodeTmp->IpBegin.uIpV4 + ipdelta_uid;

                __android_log_print(ANDROID_LOG_ERROR, TAG, "SetNetFilterRule IP = 0x%X!", pNodeTmp->IpBegin.uIpV4);
                p_Temp = strtok_r(NULL, ":", &p_strtok); // for Ports strtok_r

                if (p_Temp != NULL) {
                    __android_log_print(ANDROID_LOG_ERROR, TAG, "SetNetFilterRule Ports = %s!", p_Temp);
                    String2FilterPort(p_Temp, pNodeTmp->FlagFilter == FLAG_FILTER_BLACK ? 1 : 0,
                                      &pNodeTmp->FilterPort);
                } /*else {
                    if (pNodeTmp->FlagFilter == FLAG_FILTER_BLACK){
                        pNodeTmp->FilterPort.blCnt = 1;
                        pNodeTmp->FilterPort.BL[0].Begin = 0;
                        pNodeTmp->FilterPort.BL[0].End = 65535;
                    } else {
                        pNodeTmp->FilterPort.wlCnt = 1;
                        pNodeTmp->FilterPort.WL[0].Begin = 0;
                        pNodeTmp->FilterPort.WL[0].End = 65535;
                    }
                }*/
                nl_status = (
                        netlink_sendmsg(PACKFILTER_IOCTL_SET_FILTERIP, pNodeTmp, sizeof(SFilterIp)) >= 0);
            }
            free(pNodeTmp);
        }
            break;
        default:
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Unsupported filter type!");
            break;
    }
    (*env)->ReleaseStringUTFChars(env, ip_url, szIP_URL);
    return (nl_status>=0);
}




