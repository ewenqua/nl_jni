#ifndef __CSDKDEF_H__
#define __CSDKDEF_H__

#define CR_LIMITED_APP 1
#define CR_LIMITED_WEB 2
#define CR_LIMITED_IP  4

#define MAX_NAME_LENGTH			128
#define MAX_ITEM_COUNT			28
#define MAX_ITEM_COUNT2			152
#define MAX_CACHE_HOSTID_CNT	16

typedef int32_t TYPE_IP_V4;
typedef char TYPE_NAME[MAX_NAME_LENGTH];
typedef int FLAG_FILTER;

#define FLAG_FILTER_DEFAULT	0x00
#define	FLAG_FILTER_WHITE	0x01
#define FLAG_FILTER_BLACK	0x02

typedef int IPADDR_TYPE;

#define IPADDR_TYPE_V4	0x00
#define IPADDR_TYPE_V6	0x01

typedef struct
{
    union
    {
        TYPE_IP_V4 uIpV4;
    };
} SIpAddr;

typedef struct
{
    int nLen;
    TYPE_NAME sName;
} SHost;

typedef struct
{
    int	Begin;
    int	End;
} SPort;

typedef struct
{
    SPort	BL[MAX_ITEM_COUNT];
    int	blCnt;
    SPort	WL[MAX_ITEM_COUNT];
    int	wlCnt;
} SFilterPort;

typedef struct
{
    SIpAddr		IpBegin;
    SIpAddr		IpEnd;
    FLAG_FILTER	FlagFilter;
    SFilterPort	FilterPort;
} SFilterIp;

typedef struct
{
    __kernel_uid32_t uUid;
    FLAG_FILTER FlagFilter;
} SFilterUid;

typedef struct
{
    SHost OriHost;
    SHost Host;
    int nCount;
    SIpAddr Items[MAX_ITEM_COUNT];
    int nDotCnt;
} SDnsResp;

typedef struct
{
    SHost OriHost;
    SHost Host;
    int nCount;
    SIpAddr Items[MAX_ITEM_COUNT2];
    int nDotCnt;
} SDnsResp2;

typedef struct
{
    SHost Host;
    FLAG_FILTER	FlagFilter;
    SFilterPort	FilterPort;
} SFilterHost;

typedef SFilterUid SUidNode;

#define PACKFILTER_IOCTL_SET_FILTERIP	 	0x80	
#define PACKFILTER_IOCTL_SET_FILTERHOST 	0x81	
#define PACKFILTER_IOCTL_GET_NEWIP	 	0x82	
#define PACKFILTER_IOCTL_SET_DEFAULTFILTER	0x84	
#define PACKFILTER_IOCTL_GET_DNS_REQ_PACK	0x85	
#define PACKFILTER_IOCTL_GET_DNS_RES_PACK	0x86	
#define PACKFILTER_IOCTL_SET_ENABLED		0x87	
#define PACKFILTER_IOCTL_SET_REINIT		0x88	
#define PACKFILTER_IOCTL_SET_FILTERUID	 	0x89	
#define PACKFILTER_IOCTL_SET_CLRUID	 	0x8C	
#define PACKFILTER_IOCTL_SET_CLRIPHOST	 	0x8D	

#endif	
