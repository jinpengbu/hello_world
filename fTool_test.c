/************************************************************************
 * Basic Tools for Qice Inteligent NIC
 * 2016-12-06
 * 
 ************************************************************************/

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/types.h>
#include <math.h>
#include <inttypes.h>


static char version[] = "fTool, v3.0, 12/08/2016 Qice Corp.\n";
static const char usage_msg[] = "Usage: fTool [-f <filter.rules>] [-DV] <interface>";


#define PROMPT1(str)                  "     " str
#define PROMPT2(prompt,format)        "     %-40s" format, prompt

#define PREFIX_2_MASK(len)  ((0xFFFFFFFFUL << (32-len))&0xFFFFFFFFUL)

#define RULE_PROTO          0x01
#define RULE_SIP            0x02
#define RULE_DIP            0x04
#define RULE_SPORT          0x08
#define RULE_DPORT          0x10
#define RULE_RANGE          0x20
#define RULE_TUPLE          0x40
#define RULE_KEY            0x80
#define MAX_TUPLE_NUM       32
#define MAX_KEY_NUM         32
#define MAX_KEY_LEN         20

/* FPGA Registers */
#define CAM0_DATA           (0x00)
#define CAM1_DATA           (0x01)
#define CAM2_DATA           (0x02)
#define CAM3_DATA           (0x03)
#define CAM4_DATA           (0x04)
#define CAM0_MASK           (0x05)
#define CAM1_MASK           (0x06)
#define CAM2_MASK           (0x07)
#define CAM3_MASK           (0x08)
#define CAM4_MASK           (0x09)
#define CAM_ADDR            (0x0A)
#define TAG_MAP_REG         (0x0D)
#define SFP_ING_PKT_LO      (0x10)
#define SFP_ING_PKT_HI      (0x11)

#define SFP_ING_PKT_LO      (0x10)
#define SFP_ING_PKT_HI      (0x11)
#define SFP_ING_BYT_LO      (0x12)
#define SFP_ING_BYT_HI      (0x13)
#define PP_ING_PKT_LO       (0x14)
#define PP_ING_PKT_HI       (0x15)
#define PP_ING_BYT_LO       (0x16)
#define PP_ING_BYT_HI       (0x17)
#define PP_DIFFS            (0x08)
#define PQ_ING_PKT_LO       (0x30)
#define PQ_ING_PKT_HI       (0x31)
#define PQ_ING_BYT_LO       (0x32)
#define PQ_ING_BYT_HI       (0x33)
#define PQ_DIFFS            (0x04)

#define I2C_BASEADDR0       (0x7A)
#define I2C_BASEADDR1       (0x7B)
#define I2C_BASEADDR2       (0x7C)
#define I2C_BASEADDR3       (0x7D)

#define CARD_TYPE           (0x7E)


#ifndef SIOCGMIIPHY
#define SIOCGMIIREG         (0x8948)
#define SIOCSMIIREG         (0x8949)
#endif

#define PHY_ID              (0x07)



typedef struct tuple_key {
    uint8_t        rule_index[4];
    uint32_t       flags;
    uint8_t        proto;
    uint8_t        proto_mask;
    uint32_t       sip;
    uint32_t       sip_mask;
    uint32_t       dip;
    uint32_t       dip_mask;
    uint16_t       sport;
    uint16_t       sport_mask;
    uint16_t       dport;
    uint16_t       dport_mask;
} tuple_key_t;

typedef struct payload_key {
    uint8_t        rule_index[4];
    uint32_t       offset;
    uint8_t        value[MAX_KEY_LEN];
    uint8_t        mask[MAX_KEY_LEN];
} payloadkey_t;

typedef struct rulecfg {
    uint32_t       flags;
    uint8_t        inpbmp;
    tuple_key_t    tuple;
    payloadkey_t   keys;
} rulecfg_t;

typedef struct rulecfgs {
    int            result;
    unsigned int   num;
    rulecfg_t      rules[4*(MAX_TUPLE_NUM+MAX_KEY_NUM)];
} rulecfgs_t;

typedef struct port_stats_base {
    uint64_t       pkt_inputs_base;
    uint64_t       byt_inputs_base;
    uint64_t       pkt_filter_base;
    uint64_t       byt_filter_base;
    uint64_t       pkt_outputs_base;
    uint64_t       byt_outputs_base;    
} port_stats_base_t;//
typedef struct port_stats {
    uint64_t       pkt_inputs;
    uint64_t       byt_inputs;
    uint64_t       pkt_filter;
    uint64_t       byt_filter;
    uint64_t       pkt_outputs;
    uint64_t       byt_outputs;    
} port_stats_t;

typedef struct fpga_stats {
    port_stats_t   port[4];
    port_stats_base_t   port_base[4];//
} fpga_stats_t;

typedef struct moduleinfo {
    char           vendor_name[128];
    char           power[128];
    char           temp[128];
    char           volt[128];
} moduleinfo_t;


struct option longopts[] = {
/*  {name  has_arg  *flag  val} */
    {"debug",       0, 0, 'D'},
    {"filterfile",  1, 0, 'f'},
    {"help",        0, 0, '?'},
    {"version",     0, 0, 'V'},
    { 0, 0, 0, 0 }
};

unsigned int       debug = 0;
unsigned int       opt_f = 0;
char               opt_FileName[256] = "./filter.rules";
unsigned int       opt_version = 0;

int                skfd = -1;
struct ifreq       ifr;
rulecfgs_t         cfgs;
tuple_key_t        tuples[MAX_TUPLE_NUM];
payloadkey_t       keys[MAX_KEY_NUM];
uint8_t            tagMap[MAX_TUPLE_NUM][MAX_KEY_NUM];
int                verify_only = 0;
int                i2c_inited = 0;
int                cardtype = 0x00082599;



/*************************************************************************************
 *
 * Basic FPGA Register Access
 *
 ************************************************************************************/
static uint16_t mdio_read(uint16_t addr)
{
    uint16_t *data = (uint16_t *)(&ifr.ifr_data);
    
    if (verify_only == 0) {
        data[0] = PHY_ID;
        data[1] = addr;
        if (ioctl(skfd, SIOCGMIIREG, &ifr) < 0) {
            printf(PROMPT1("ioctl SIOCGMIIREG failed!\n"));
            exit(-1);
        }
        return data[3];
    } else
        return 0;
}

static uint16_t mdio_write(uint16_t addr, uint16_t value)
{
    uint16_t *data = (uint16_t *)(&ifr.ifr_data);
    
    if (verify_only == 0) {
        data[0] = PHY_ID;
        data[1] = addr;
        data[2] = value;
        if (ioctl(skfd, SIOCSMIIREG, &ifr) < 0) {
            printf(PROMPT1("ioctl SIOCSMIIREG failed!\n"));
            exit(-1);
        }
    }
    return 0;
}

static uint32_t reg_read(uint32_t addr)
{
    uint32_t value_lo, value_hi;
    
    /* step 1, write offset to REG 1, issue read cmd */
    mdio_write(0x1, (addr + 0x0000));   /* bit 12: 0 is read, 1 is write */    
    /* step 2, read REG 4, get value_lo */
    value_lo = mdio_read(0x4);
    /* step 3, read REG 5, get value_hi */
    value_hi = mdio_read(0x5);
    return (((value_hi << 16)&0xffff0000)|(value_lo&0x0000ffff));
}

static uint32_t reg_write(uint32_t addr, uint32_t value)
{
    /* step 1, write value_lo to REG 2 */
    mdio_write(0x2, (uint16_t)(value&0xffff));
    /* step 2, write value_hi to REG 3 */
    mdio_write(0x3, (uint16_t)((value>>16)&0xffff));
    /* step 3, write offset to REG 1, issue write cmd */
    mdio_write(0x1, (uint16_t)(addr+0x1000));
    return 0;
}


/*************************************************************************************
 *
 * Filter Rules
 *
 ************************************************************************************/
static int rules_check()
{
    int loops, check_flag;
    int i, j, checkpass, find, num;
    
    for (loops = 0; loops < 4; loops++) {
        memset(tuples, 0, sizeof(tuple_key_t)*MAX_TUPLE_NUM);
        num = 0;
        for (i = 0; i < cfgs.num; i++) {
            check_flag = cfgs.rules[i].inpbmp & (0x1<<loops);
            if ((cfgs.rules[i].flags & RULE_TUPLE) && (check_flag)) {
                find = 0;
                for (j = 0; j < num; j++) {
                    if (cfgs.rules[i].tuple.flags == tuples[j].flags) {
                        if (((cfgs.rules[i].tuple.flags & RULE_PROTO) == 0) || 
                            (cfgs.rules[i].tuple.proto == tuples[j].proto))
                            checkpass = 1;
                        else
                            checkpass = 0;
                        if (checkpass &&(((cfgs.rules[i].tuple.flags & RULE_SIP) == 0) || 
                            ((cfgs.rules[i].tuple.sip == tuples[j].sip) &&
                             (cfgs.rules[i].tuple.sip_mask == tuples[j].sip_mask))))
                            checkpass = 1;
                        else
                            checkpass = 0;
                        if (checkpass &&(((cfgs.rules[i].tuple.flags & RULE_DIP) == 0) || 
                            ((cfgs.rules[i].tuple.dip == tuples[j].dip) &&
                             (cfgs.rules[i].tuple.dip_mask == tuples[j].dip_mask))))
                            checkpass = 1;
                        else
                            checkpass = 0;
                        if (checkpass &&(((cfgs.rules[i].tuple.flags & RULE_SPORT) == 0) || 
                            ((cfgs.rules[i].tuple.sport == tuples[j].sport) &&
                             (cfgs.rules[i].tuple.sport_mask == tuples[j].sport_mask))))
                            checkpass = 1;
                        else
                            checkpass = 0;
                        if (checkpass &&(((cfgs.rules[i].tuple.flags & RULE_DPORT) == 0) || 
                            ((cfgs.rules[i].tuple.dport == tuples[j].dport) &&
                             (cfgs.rules[i].tuple.dport_mask == tuples[j].dport_mask))))
                            checkpass = 1;
                        else
                            checkpass = 0;
                        if (checkpass == 1) {
                            cfgs.rules[i].tuple.rule_index[loops] = j;
                            find = 1;
                            break;
                        }
                    }
                } /* for (j = 0; j < num; j++) { */
                if (find == 0) {
                    if (num < MAX_TUPLE_NUM -1) {
                        tuples[num].flags = cfgs.rules[i].tuple.flags;
                        tuples[num].proto = cfgs.rules[i].tuple.proto;
                        tuples[num].sip = cfgs.rules[i].tuple.sip;
                        tuples[num].sip_mask = cfgs.rules[i].tuple.sip_mask;
                        tuples[num].dip = cfgs.rules[i].tuple.dip;
                        tuples[num].dip_mask = cfgs.rules[i].tuple.dip_mask;
                        tuples[num].sport = cfgs.rules[i].tuple.sport;
                        tuples[num].sport_mask = cfgs.rules[i].tuple.sport_mask;
                        tuples[num].dport = cfgs.rules[i].tuple.dport;
                        tuples[num].dport_mask = cfgs.rules[i].tuple.dport_mask;
                        cfgs.rules[i].tuple.rule_index[loops] = num;
                    } else {
                        cfgs.result = -2;
                        return -1;
                    }
                    num++;
                }
            }
        }
    }
    for (loops = 0; loops < 4; loops++) {
        memset(keys, 0, sizeof(payloadkey_t)*MAX_KEY_NUM);
        num = 0;
        for (i = 0; i < cfgs.num; i++) {
            check_flag = cfgs.rules[i].inpbmp & (0x1<<loops);
            if ((cfgs.rules[i].flags & RULE_KEY) && (check_flag)) {
                find = 0;
                for (j = 0; j < num; j++) {
                    if ((cfgs.rules[i].keys.offset == keys[j].offset) &&
                        (memcmp(cfgs.rules[i].keys.value, keys[j].value, MAX_KEY_LEN) == 0)) {
                        cfgs.rules[i].keys.rule_index[loops] = j;
                        find = 1;
                        break;
                    }
                }
                if (find == 0) {
                    if (num < MAX_KEY_NUM -1) {
                        keys[num].offset = cfgs.rules[i].keys.offset;
                        memcpy(keys[num].value, cfgs.rules[i].keys.value, MAX_KEY_LEN);
                        cfgs.rules[i].keys.rule_index[loops] = num;
                    } else {
                        cfgs.result = -3;
                        return -1;
                    }
                    num++;
                }
            }
        }
    }
    return 0;
}

static int rules_load()
{
    unsigned int i, j, dotnum=0, rulenum=0, linenum=0;
    unsigned int ip1,ip2,ip3,ip4,len,port,mask;
    char buf[256], str_inport[32], str_proto[32];
    char str_sip[32], str_dip[32], str_sport[32], str_dport[32];
    char str_key_off[256], str_key[256], keywd_fs, keywd_ls;
    char *keys;
    FILE *fp;
    
    cfgs.result = 0;
    if ((fp = fopen(opt_FileName, "r")) == NULL) {
        printf(PROMPT1("Can't open rule config file %s!\n"), opt_FileName);
        return -1;
    }
    while (fgets(buf, 256, fp)) {
        linenum++;
        if ((buf[0] == '#') || (buf[0] == '\n') || (buf[0] == '\r'))
            continue;
        dotnum = 0;
        for (i = 0; i < strlen(buf); i++)
            if (buf[i] == ',')
                dotnum++;
        if (dotnum != 7) {
            cfgs.result = linenum;
            return 0;
        }
        i = 0;
        keys = strtok(buf, ", ");
        strcpy(str_inport, keys);
        while (i < 7) {
            keys = strtok(NULL, ", ");
            switch (i) {
            case 0: strcpy(str_proto, keys); break;
            case 1: strcpy(str_sip, keys); break;
            case 2: strcpy(str_dip, keys); break;
            case 3: strcpy(str_sport, keys); break;
            case 4: strcpy(str_dport, keys); break;
            case 5: strcpy(str_key_off, keys); break;
            case 6: strcpy(str_key, keys); break;
            default: break;
            }
            i++;
        }
        /* inports */
        if (strcmp(str_inport, "*"))
            cfgs.rules[rulenum].inpbmp = strtol(str_inport, NULL, 16)&0x0f;
        else
            cfgs.rules[rulenum].inpbmp = 0x0f;
        /* protocol, mask is active low */
        if (strcmp(str_proto, "*")) {
            cfgs.rules[rulenum].flags |= RULE_TUPLE;
            cfgs.rules[rulenum].tuple.flags |= RULE_PROTO;
            cfgs.rules[rulenum].tuple.proto = atoi(str_proto);
            cfgs.rules[rulenum].tuple.proto_mask = 0x0;
        } else
            cfgs.rules[rulenum].tuple.proto_mask = 0xff;
        /* sip, mask is active low */
        len = 32;
        if (strcmp(str_sip, "*")) {
            if (strchr(str_sip, '/') != 0)
                sscanf(str_sip, "%d.%d.%d.%d/%d", &ip1,&ip2,&ip3,&ip4,&len);
            else
                sscanf(str_sip, "%d.%d.%d.%d", &ip1,&ip2,&ip3,&ip4);
            cfgs.rules[rulenum].flags |= RULE_TUPLE;
            cfgs.rules[rulenum].tuple.flags |= RULE_SIP;
            cfgs.rules[rulenum].tuple.sip = (ip1<<24) + (ip2<<16) + (ip3<<8) + ip4;
            cfgs.rules[rulenum].tuple.sip_mask = ~(PREFIX_2_MASK(len));
        } else
            cfgs.rules[rulenum].tuple.sip_mask = 0xffffffff;
        /* dip, mask is active low */
        len = 32;
        if (strcmp(str_dip, "*")) {
            if (strchr(str_dip, '/') != 0)
                sscanf(str_dip, "%d.%d.%d.%d/%d", &ip1,&ip2,&ip3,&ip4,&len);
            else
                sscanf(str_dip, "%d.%d.%d.%d", &ip1,&ip2,&ip3,&ip4);
            cfgs.rules[rulenum].flags |= RULE_TUPLE;
            cfgs.rules[rulenum].tuple.flags |= RULE_DIP;
            cfgs.rules[rulenum].tuple.dip = (ip1<<24) + (ip2<<16) + (ip3<<8) + ip4;
            cfgs.rules[rulenum].tuple.dip_mask = ~(PREFIX_2_MASK(len));
        } else
            cfgs.rules[rulenum].tuple.dip_mask = 0xffffffff;
        /* sport, mask is active low */
        mask = 0xffff;
        if (strcmp(str_sport, "*")) {
            if (strchr(str_sport, '/') != 0)
                sscanf(str_sport, "%d/0x%x", &port,&mask);
            else
                sscanf(str_sport, "%d", &port);
            cfgs.rules[rulenum].flags |= RULE_TUPLE;
            cfgs.rules[rulenum].tuple.flags |= RULE_SPORT;
            cfgs.rules[rulenum].tuple.sport = port;
            cfgs.rules[rulenum].tuple.sport_mask = ~mask;
        } else
            cfgs.rules[rulenum].tuple.sport_mask = 0xffff;
        /* dport, mask is active low */
        mask = 0xffff;
        if (strcmp(str_dport, "*")) {
            if (strchr(str_dport, '/') != 0)
                sscanf(str_dport, "%d/0x%x", &port,&mask);
            else
                sscanf(str_dport, "%d", &port);
            cfgs.rules[rulenum].flags |= RULE_TUPLE;
            cfgs.rules[rulenum].tuple.flags |= RULE_DPORT;
            cfgs.rules[rulenum].tuple.dport = port;
            cfgs.rules[rulenum].tuple.dport_mask = ~mask;
        } else
            cfgs.rules[rulenum].tuple.dport_mask = 0xffff;
        /* key offset */
        if (strcmp(str_key_off, "*"))
            cfgs.rules[rulenum].keys.offset = atoi(str_key_off);
        else
            cfgs.rules[rulenum].keys.offset = 0;
        /* keys */
        if (strncmp(str_key, "*", 1)) {
            if ((strlen(str_key) >= 1) && (str_key[strlen(str_key)-1] == 0x0a))
                str_key[strlen(str_key)-1] = '\0';
            if ((strlen(str_key) >= 1) && (str_key[strlen(str_key)-1] == 0x0d))
                str_key[strlen(str_key)-1] = '\0';
            if (strlen(str_key)%2) { /* half byte ? */
                cfgs.result = linenum;
                return 0;
            }
            cfgs.rules[rulenum].flags |= RULE_KEY;
            memset(cfgs.rules[rulenum].keys.value, 0x0, MAX_KEY_LEN);
            memset(cfgs.rules[rulenum].keys.mask, 0xff, MAX_KEY_LEN); /* match everything */
            for (i = 0, j = cfgs.rules[rulenum].keys.offset; i < strlen(str_key); j++) {
                if ((str_key[i] >= 0x30) && (str_key[i] <= 0x39)) /* 0 - 9 */
                    keywd_fs = str_key[i] - 0x30;
                else if ((str_key[i] >= 0x41) && (str_key[i] <= 0x46)) /* A - F */
                    keywd_fs = str_key[i] - 0x37;
                else if ((str_key[i] >= 0x61) && (str_key[i] <= 0x66)) /* a - f */
                    keywd_fs = str_key[i] - 0x57;
                else {
                    cfgs.result = linenum;
                    return 0;
                }
                if ((str_key[i+1] >= 0x30) && (str_key[i+1] <= 0x39))
                    keywd_ls = str_key[i+1] - 0x30;
                else if ((str_key[i+1] >= 0x41) && (str_key[i+1] <= 0x46))
                    keywd_ls = str_key[i+1] - 0x37;
                else if ((str_key[i] >= 0x61) && (str_key[i] <= 0x66)) /* a - f */
                    keywd_ls = str_key[i+1] - 0x57;
                else {
                    cfgs.result = linenum;
                    return 0;
                }
                cfgs.rules[rulenum].keys.value[j] = ((keywd_fs << 4) & 0xf0)|(keywd_ls & 0xf);
                i+=2;
            }
            for (i = cfgs.rules[rulenum].keys.offset; i < (cfgs.rules[rulenum].keys.offset + strlen(str_key)/2); i++)
                cfgs.rules[rulenum].keys.mask[i] = 0x00;
        } else
            for (i = 0; i < MAX_KEY_LEN; i++)
                cfgs.rules[rulenum].keys.mask[i] = 0xff;
        rulenum++;
    }
    cfgs.num = rulenum;
    fclose(fp);
    return 0;
}

int rules_install()
{
    int      rule1_index, rule2_index, i, j, loops, check_flag;
    uint32_t data;
    FILE     *fp;
    
    rules_load();
    
    if (cfgs.result == 0)
        rules_check();
    
    /* rules checking result */
    switch (cfgs.result) {
    case  0: printf(PROMPT1("Filter Rules Checking Passed!\n")); break;
    case -2: printf(PROMPT1("Filter Rules Checking Failed! Too Many Tuple rules (>=32)!\n")); return -1;
    case -3: printf(PROMPT1("Filter Rules Checking Failed! Too Many Payload Rules (>=32)!\n")); return -1;
    default: printf(PROMPT1("Filter Rules Checking Failed! Syntax Error at line %d\n"), cfgs.result); return -1;
    }
    
    if ((fp = fopen(".TCAM.DUMP", "w+")) == NULL) {
        printf(PROMPT1("Can't open rule config file %s!\n"), ".TCAM.DUMP");
        return -1;
    }
    fprintf(fp, "*****************************************************************\n");
    /* update tuple cam */
    for (loops = 0; loops < 4; loops++) {
        fprintf(fp, "TUPLE TCAM for Port %d\n", (loops+1));
        rule1_index = -1;
        for (i = 0; i < cfgs.num; i++) {
            if (cfgs.rules[i].flags & RULE_TUPLE) {
                check_flag = cfgs.rules[i].inpbmp & (0x1<<loops);
                if ((cfgs.rules[i].tuple.rule_index[loops] > rule1_index) && (check_flag)) {
                    rule1_index = cfgs.rules[i].tuple.rule_index[loops];
                    /* cam mask, '0' care, '1' don't care */
                    data = (((uint32_t)cfgs.rules[i].tuple.proto_mask<<24)&0xff000000)|
                           (((uint32_t)cfgs.rules[i].tuple.sip_mask>>8)&0x00ffffff);
                    reg_write(CAM4_MASK, data);
                    fprintf(fp, "MASK: %08x ", data);
                    data = (((uint32_t)cfgs.rules[i].tuple.sip_mask<<24)&0xff000000)|
                           (((uint32_t)cfgs.rules[i].tuple.dip_mask>>8)&0x00ffffff);
                    reg_write(CAM3_MASK, data);
                    fprintf(fp, "%08x ", data);
                    data = (((uint32_t)cfgs.rules[i].tuple.dip_mask<<24)&0xff000000) |
                           (((uint32_t)cfgs.rules[i].tuple.sport_mask<<8)&0x00ffff00)|
                           (((uint32_t)cfgs.rules[i].tuple.dport_mask>>8)&0x000000ff);
                    reg_write(CAM2_MASK, data);
                    fprintf(fp, "%08x ", data);
                    data = (((uint32_t)cfgs.rules[i].tuple.dport_mask<<24)&0xff000000)|0x00ffffff;
                    reg_write(CAM1_MASK, data);
                    fprintf(fp, "%08x ", data);
                    data = 0xffffffff;
                    reg_write(CAM0_MASK, data);
                    fprintf(fp, "%08x\n", data);
                    /* cam data */
                    data = (((uint32_t)cfgs.rules[i].tuple.proto<<24)&0xff000000)|
                           (((uint32_t)cfgs.rules[i].tuple.sip>>8)&0x00ffffff);
                    reg_write(CAM4_DATA, data);
                    fprintf(fp, "DATA: %08x ", data);
                    data = (((uint32_t)cfgs.rules[i].tuple.sip<<24)&0xff000000)|
                           (((uint32_t)cfgs.rules[i].tuple.dip>>8)&0x00ffffff);
                    reg_write(CAM3_DATA, data);
                    fprintf(fp, "%08x ", data);
                    data = (((uint32_t)cfgs.rules[i].tuple.dip<<24)&0xff000000)|
                           (((uint32_t)cfgs.rules[i].tuple.sport<<8)&0x00ffff00)|
                           (((uint32_t)cfgs.rules[i].tuple.dport>>8)&0x000000ff);
                    reg_write(CAM2_DATA, data);
                    fprintf(fp, "%08x ", data);
                    data = (((uint32_t)cfgs.rules[i].tuple.dport<<24)&0xff000000);
                    reg_write(CAM1_DATA, data);
                    fprintf(fp, "%08x ", data);
                    data = 0x0;
                    reg_write(CAM0_DATA, data);
                    fprintf(fp, "%08x ", data);
                    for (j = 0; j < 10; j++) {
                        data = reg_read(CAM_ADDR);
                        if ((data & 0x80000000) == 0x0)
                            break;
                        else
                            usleep(10);
                    }
                    if (j == 10) {
                        printf(PROMPT1("TCAM busy, Write Tuple TCAM failed!\n"));
                        return -1;
                    }
                    data = rule1_index|0x80000000|((loops << 6)&0xc0); /* loops indicate which cam to write */
                    reg_write(CAM_ADDR, data);
                    fprintf(fp, " => %08x\n", data);
                }
            }
        }
        i = rule1_index + 1;
        while (i < MAX_TUPLE_NUM) {
            /* mask */
            reg_write(CAM4_MASK, 0x0);
            reg_write(CAM3_MASK, 0x0);
            reg_write(CAM2_MASK, 0x0);
            reg_write(CAM1_MASK, 0x0);
            reg_write(CAM0_MASK, 0x0);
            /* data */
            reg_write(CAM4_DATA, 0x0);
            reg_write(CAM3_DATA, 0x0);
            reg_write(CAM2_DATA, 0x0);
            reg_write(CAM1_DATA, 0x0);
            reg_write(CAM0_DATA, 0x0);
            for (j = 0; j < 10; j++) {
                data = reg_read(CAM_ADDR);
                if ((data & 0x80000000) == 0x0)
                    break;
                else
                    usleep(10);
            }
            if (j == 10) {
                printf(PROMPT1("TCAM busy, Write Tuple TCAM failed!\n"));
                return -1;
            }
            data = i | 0x80000000 | ((loops << 6) & 0xc0);  /* loops indicate which cam to write */
            reg_write(CAM_ADDR, data);
            i++;
        }
        fprintf(fp, "\n");
    }
    fprintf(fp, "*****************************************************************\n");
    /* update keyword cam */
    for (loops = 0; loops < 4; loops++) {
        fprintf(fp, "PAYLOAD KEY TCAM for Port %d\n", (loops+1));
        rule2_index = -1;
        for (i = 0; i < cfgs.num; i++) {
            if (cfgs.rules[i].flags & RULE_KEY) {
                check_flag = cfgs.rules[i].inpbmp & (0x1<<loops);
                if ((cfgs.rules[i].keys.rule_index[loops] > rule2_index) && (check_flag)) {
                    rule2_index = cfgs.rules[i].keys.rule_index[loops];
                    /* cam mask, '0' care, '1' don't care */
                    data = ((uint32_t)cfgs.rules[i].keys.mask[0] << 24) |
                           ((uint32_t)cfgs.rules[i].keys.mask[1] << 16) |
                           ((uint32_t)cfgs.rules[i].keys.mask[2] << 8)  |
                           ((uint32_t)cfgs.rules[i].keys.mask[3]);
                    reg_write(CAM4_MASK, data);
                    fprintf(fp, "MASK: %08x ", data);
                    data = ((uint32_t)cfgs.rules[i].keys.mask[4] << 24) |
                           ((uint32_t)cfgs.rules[i].keys.mask[5] << 16) |
                           ((uint32_t)cfgs.rules[i].keys.mask[6] << 8)  |
                           ((uint32_t)cfgs.rules[i].keys.mask[7]);
                    reg_write(CAM3_MASK, data);
                    fprintf(fp, "%08x ", data);
                    data = ((uint32_t)cfgs.rules[i].keys.mask[8] << 24) |
                           ((uint32_t)cfgs.rules[i].keys.mask[9] << 16) |
                           ((uint32_t)cfgs.rules[i].keys.mask[10]<< 8)  |
                           ((uint32_t)cfgs.rules[i].keys.mask[11]);
                    reg_write(CAM2_MASK, data);
                    fprintf(fp, "%08x ", data);
                    data = ((uint32_t)cfgs.rules[i].keys.mask[12] << 24)|
                           ((uint32_t)cfgs.rules[i].keys.mask[13] << 16)|
                           ((uint32_t)cfgs.rules[i].keys.mask[14] << 8) |
                           ((uint32_t)cfgs.rules[i].keys.mask[15]);
                    reg_write(CAM1_MASK, data);
                    fprintf(fp, "%08x ", data);
                    data = ((uint32_t)cfgs.rules[i].keys.mask[16] << 24)|
                           ((uint32_t)cfgs.rules[i].keys.mask[17] << 16)|
                           ((uint32_t)cfgs.rules[i].keys.mask[18] << 8) |
                           ((uint32_t)cfgs.rules[i].keys.mask[19]); 
                    reg_write(CAM0_MASK, data);
                    fprintf(fp, "%08x\n", data);
                    /* cam data */
                    data = ((uint32_t)cfgs.rules[i].keys.value[0] << 24)|
                           ((uint32_t)cfgs.rules[i].keys.value[1] << 16)|
                           ((uint32_t)cfgs.rules[i].keys.value[2] << 8) |
                           ((uint32_t)cfgs.rules[i].keys.value[3]);
                    reg_write(CAM4_DATA, data);
                    fprintf(fp, "DATA: %08x ", data);
                    data = ((uint32_t)cfgs.rules[i].keys.value[4] << 24)|
                           ((uint32_t)cfgs.rules[i].keys.value[5] << 16)|
                           ((uint32_t)cfgs.rules[i].keys.value[6] << 8) |
                           ((uint32_t)cfgs.rules[i].keys.value[7]);
                    reg_write(CAM3_DATA, data);
                    fprintf(fp, "%08x ", data);
                    data = ((uint32_t)cfgs.rules[i].keys.value[8] << 24)|
                           ((uint32_t)cfgs.rules[i].keys.value[9] << 16)|
                           ((uint32_t)cfgs.rules[i].keys.value[10]<< 8) |
                           ((uint32_t)cfgs.rules[i].keys.value[11]);
                    reg_write(CAM2_DATA, data);
                    fprintf(fp, "%08x ", data);
                    data = ((uint32_t)cfgs.rules[i].keys.value[12]<< 24)|
                           ((uint32_t)cfgs.rules[i].keys.value[13]<< 16)|
                           ((uint32_t)cfgs.rules[i].keys.value[14]<< 8) |
                           ((uint32_t)cfgs.rules[i].keys.value[15]);
                    reg_write(CAM1_DATA, data);
                    fprintf(fp, "%08x ", data);
                    data = ((uint32_t)cfgs.rules[i].keys.value[16]<< 24)|
                           ((uint32_t)cfgs.rules[i].keys.value[17]<< 16)|
                           ((uint32_t)cfgs.rules[i].keys.value[18]<< 8) |
                           ((uint32_t)cfgs.rules[i].keys.value[19]); 
                    reg_write(CAM0_DATA, data);
                    fprintf(fp, "%08x ", data);
                    for (j = 0; j < 10; j++) {
                        data = reg_read(CAM_ADDR);
                        if ((data & 0x80000000) == 0x0)
                            break;
                        else
                            usleep(10);
                    }
                    if (j == 10) {
                        printf(PROMPT1("TCAM busy, Write Paylod TCAM failed!\n"));
                        return -1;
                    }
                    data = rule2_index | 0x80000020 | ((loops << 6) & 0xc0);  /* loops indicate which cam to write */
                    reg_write(CAM_ADDR, data);
                    fprintf(fp, " => %08x\n", data);
                }
            }
        }
        i = rule2_index + 1;
        while (i < MAX_KEY_NUM) {
            reg_write(CAM4_MASK, 0x0);
            reg_write(CAM3_MASK, 0x0);
            reg_write(CAM2_MASK, 0x0);
            reg_write(CAM1_MASK, 0x0);
            reg_write(CAM0_MASK, 0x0);
            reg_write(CAM4_DATA, 0x0);
            reg_write(CAM3_DATA, 0x0);
            reg_write(CAM2_DATA, 0x0);
            reg_write(CAM1_DATA, 0x0);
            reg_write(CAM0_DATA, 0x0);
            for (j = 0; j < 10; j++) {
                data = reg_read(CAM_ADDR);
                if ((data & 0x80000000) == 0x0)
                    break;
                else
                    usleep(10);
            }
            if (j == 10) {
                printf(PROMPT1("TCAM busy, Write Paylod TCAM failed!\n"));
                return -1;
            }
            data = i | 0x80000020 | ((loops << 6) & 0xc0);  /* loops indicate which cam to write */
            reg_write(CAM_ADDR, data);
            i++;
        }
        fprintf(fp, "\n");
    }
    /* update four lookup tables */
    fprintf(fp, "*****************************************************************\n");
	for (loops = 0; loops < 4; loops++) {
		fprintf(fp, "TAG MAPs for Port %d\n", (loops+1));
		for (i = 0; i < MAX_TUPLE_NUM; i++)
			for (j = 0; j < MAX_KEY_NUM; j++) {
				data = (i << 5)|(j)|0x10C00|(loops << 14);  /* default drop, bit 16 is write */
				reg_write(TAG_MAP_REG, data);
				tagMap[i][j] = 0x2;
				usleep(10);
			}
		for (i = 0; i < cfgs.num; i++) {
			if ((cfgs.rules[i].flags & RULE_TUPLE) && (cfgs.rules[i].flags & RULE_KEY)) {
				if (cfgs.rules[i].inpbmp & (0x1 << loops)) {
					data = (cfgs.rules[i].tuple.rule_index[loops] << 5)|
						(cfgs.rules[i].keys.rule_index[loops])|0x10000|(loops << 14);  /* not drop */
					reg_write(TAG_MAP_REG, data);
					tagMap[cfgs.rules[i].tuple.rule_index[loops]][cfgs.rules[i].keys.rule_index[loops]] = 0x0;
					usleep(10);
				}
			} else if (cfgs.rules[i].flags & RULE_TUPLE) {
				for (j = 0; j < MAX_KEY_NUM; j++) {
					if (cfgs.rules[i].inpbmp & (0x1 << loops)) {
						data = (cfgs.rules[i].tuple.rule_index[loops] << 5)|
							(j)|0x10000|(loops << 14);
						reg_write(TAG_MAP_REG, data);
						tagMap[cfgs.rules[i].tuple.rule_index[loops]][j] = 0x0;
						usleep(10);
					}
				}
			} else if (cfgs.rules[i].flags & RULE_KEY) {
				for (j = 0; j < MAX_TUPLE_NUM; j++) {
					if (cfgs.rules[i].inpbmp & (0x1 << loops)) {
						data = (j << 5)|(cfgs.rules[i].keys.rule_index[loops])|0x10000|(loops << 14);
						reg_write(TAG_MAP_REG, data);
						tagMap[j][cfgs.rules[i].keys.rule_index[loops]] = 0x0;
						usleep(10);
					}
				} /* for (j = 0; j < MAX_TUPLE_NUM */
			} /* else if */
		}
		/* print tagMap */
		for (i = 0; i < MAX_TUPLE_NUM; i++) {
			for (j = 0; j < MAX_KEY_NUM; j++)
				fprintf(fp, "%01x ", tagMap[i][j]);
			fprintf(fp, "\n");
		}
		fprintf(fp, "\n");
	}
	fclose(fp);
	return 0;
}

int rules_remove()
{
	int loops,i,j;
	uint32_t data;
	for (loops = 0; loops < 4; loops++) 
	{
		for (i = 0; i < MAX_TUPLE_NUM; i++)
			for (j = 0; j < MAX_KEY_NUM; j++) 
			{
				data = (i << 5)|(j)|0x10000|(loops << 14);  /*  not drop, bit 16 is write */
				reg_write(TAG_MAP_REG, data);
				tagMap[i][j] = 0x0;
				usleep(10);
			}
	}
	printf("Rules remove OK!\n");
	return 0;
}
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  fpga_statistics_base_init
 *  Description:  
 * =====================================================================================
 */
static int fpga_statistics_base_init(fpga_stats_t **stats_b)
{
	int           i;
	fpga_stats_t  *stats = *stats_b;
	/* get stats */
	for (i = 0; i < 4; i++) 
	{
		stats->port_base[i].pkt_inputs_base = 0x0;
		stats->port_base[i].byt_inputs_base = 0x0;
		stats->port_base[i].pkt_filter_base = 0x0;
		stats->port_base[i].byt_filter_base = 0x0;
	}

	for (i = 0; i < 4; i++) 
	{
		stats->port_base[i].pkt_outputs_base = 0x0;
		stats->port_base[i].byt_outputs_base = 0x0;
	}
	return 0;
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  fpga_statistics_base
 *  Description:  
 * =====================================================================================
 */
static int fpga_statistics_base(fpga_stats_t **stats_b)
{
	int           i;
	fpga_stats_t  *stats = *stats_b;
	uint64_t      value_lo, value_hi;
		/* get stats */
	for (i = 0; i < 4; i++) {
		value_lo = (uint64_t)reg_read(SFP_ING_PKT_LO + i*PP_DIFFS);
		value_hi = (uint64_t)reg_read(SFP_ING_PKT_HI + i*PP_DIFFS);
		stats->port_base[i].pkt_inputs_base = ((value_hi << 32) & 0xffffffff00000000ULL)|(value_lo & 0x00000000ffffffffULL);
		value_lo = (uint64_t)reg_read(SFP_ING_BYT_LO + i*PP_DIFFS);
		value_hi = (uint64_t)reg_read(SFP_ING_BYT_HI + i*PP_DIFFS);
		stats->port_base[i].byt_inputs_base = ((value_hi << 32) & 0xffffffff00000000ULL)|(value_lo & 0x00000000ffffffffULL);
		value_lo = (uint64_t)reg_read(PP_ING_PKT_LO + i*PP_DIFFS);
		value_hi = (uint64_t)reg_read(PP_ING_PKT_HI + i*PP_DIFFS);
		stats->port_base[i].pkt_filter_base = ((value_hi << 32) & 0xffffffff00000000ULL)|(value_lo & 0x00000000ffffffffULL);
		value_lo = (uint64_t)reg_read(PP_ING_BYT_LO + i*PP_DIFFS);
		value_hi = (uint64_t)reg_read(PP_ING_BYT_HI + i*PP_DIFFS);
		stats->port_base[i].byt_filter_base = ((value_hi << 32) & 0xffffffff00000000ULL)|(value_lo & 0x00000000ffffffffULL);
	}

	for (i = 0; i < 4; i++) {
		value_lo = (uint64_t)reg_read(PQ_ING_PKT_LO + i*PQ_DIFFS);
        value_hi = (uint64_t)reg_read(PQ_ING_PKT_HI + i*PQ_DIFFS);
        stats->port_base[i].pkt_outputs_base = ((value_hi << 32) & 0xffffffff00000000ULL)|(value_lo & 0x00000000ffffffffULL);
        value_lo = (uint64_t)reg_read(PQ_ING_BYT_LO + i*PQ_DIFFS);
        value_hi = (uint64_t)reg_read(PQ_ING_BYT_HI + i*PQ_DIFFS);
        stats->port_base[i].byt_outputs_base = ((value_hi << 32) & 0xffffffff00000000ULL)|(value_lo & 0x00000000ffffffffULL);
    }
	return 0;
}

/*************************************************************************************
 *
 * FPGA Statistics
 *
 ************************************************************************************/
static int show_fpga_statistics(fpga_stats_t **stats_b)
{
    int           i;
    fpga_stats_t  *stats = *stats_b;
    uint64_t      value_lo, value_hi;
    
    /* get stats */
    for (i = 0; i < 4; i++) {
        value_lo = (uint64_t)reg_read(SFP_ING_PKT_LO + i*PP_DIFFS);
        value_hi = (uint64_t)reg_read(SFP_ING_PKT_HI + i*PP_DIFFS);
        stats->port[i].pkt_inputs = ((value_hi << 32) & 0xffffffff00000000ULL)|(value_lo & 0x00000000ffffffffULL);
        value_lo = (uint64_t)reg_read(SFP_ING_BYT_LO + i*PP_DIFFS);
        value_hi = (uint64_t)reg_read(SFP_ING_BYT_HI + i*PP_DIFFS);
        stats->port[i].byt_inputs = ((value_hi << 32) & 0xffffffff00000000ULL)|(value_lo & 0x00000000ffffffffULL);
        value_lo = (uint64_t)reg_read(PP_ING_PKT_LO + i*PP_DIFFS);
        value_hi = (uint64_t)reg_read(PP_ING_PKT_HI + i*PP_DIFFS);
        stats->port[i].pkt_filter = ((value_hi << 32) & 0xffffffff00000000ULL)|(value_lo & 0x00000000ffffffffULL);
        value_lo = (uint64_t)reg_read(PP_ING_BYT_LO + i*PP_DIFFS);
        value_hi = (uint64_t)reg_read(PP_ING_BYT_HI + i*PP_DIFFS);
        stats->port[i].byt_filter = ((value_hi << 32) & 0xffffffff00000000ULL)|(value_lo & 0x00000000ffffffffULL);
    }
    
    for (i = 0; i < 4; i++) {
        value_lo = (uint64_t)reg_read(PQ_ING_PKT_LO + i*PQ_DIFFS);
        value_hi = (uint64_t)reg_read(PQ_ING_PKT_HI + i*PQ_DIFFS);
        stats->port[i].pkt_outputs = ((value_hi << 32) & 0xffffffff00000000ULL)|(value_lo & 0x00000000ffffffffULL);
        value_lo = (uint64_t)reg_read(PQ_ING_BYT_LO + i*PQ_DIFFS);
        value_hi = (uint64_t)reg_read(PQ_ING_BYT_HI + i*PQ_DIFFS);
		stats->port[i].byt_outputs = ((value_hi << 32) & 0xffffffff00000000ULL)|(value_lo & 0x00000000ffffffffULL);
	}

	/* print stats */
	printf(PROMPT1("%8s  %-17s  %-17s  %-17s  %-17s\n"), "PORT", "1", "2", "3", "4");
	printf(PROMPT1("------------------------------------------------------------------------------------\n"));
	printf(PROMPT1("%8s  %-17llu  %-17llu  %-17llu  %-17llu\n"), "IN PKTS", 
			(unsigned long long)stats->port[0].pkt_inputs - (unsigned long long)stats->port_base[0].pkt_inputs_base, 
			(unsigned long long)stats->port[1].pkt_inputs - (unsigned long long)stats->port_base[1].pkt_inputs_base,
			(unsigned long long)stats->port[2].pkt_inputs - (unsigned long long)stats->port_base[2].pkt_inputs_base,
			(unsigned long long)stats->port[3].pkt_inputs - (unsigned long long)stats->port_base[3].pkt_inputs_base);
	printf(PROMPT1("%8s  %-17llu  %-17llu  %-17llu  %-17llu\n"), "IN BYTE", 
			(unsigned long long)stats->port[0].byt_inputs - (unsigned long long)stats->port_base[0].byt_inputs_base, 
			(unsigned long long)stats->port[1].byt_inputs - (unsigned long long)stats->port_base[1].byt_inputs_base, 
			(unsigned long long)stats->port[2].byt_inputs - (unsigned long long)stats->port_base[2].byt_inputs_base, 
			(unsigned long long)stats->port[3].byt_inputs - (unsigned long long)stats->port_base[3].byt_inputs_base);
	printf(PROMPT1("%8s  %-17llu  %-17llu  %-17llu  %-17llu\n"), "FLT PKTS", 
			(unsigned long long)stats->port[0].pkt_filter - (unsigned long long)stats->port_base[0].pkt_filter_base, 
			(unsigned long long)stats->port[1].pkt_filter - (unsigned long long)stats->port_base[1].pkt_filter_base, 
			(unsigned long long)stats->port[2].pkt_filter - (unsigned long long)stats->port_base[2].pkt_filter_base, 
			(unsigned long long)stats->port[3].pkt_filter - (unsigned long long)stats->port_base[3].pkt_filter_base);
	printf(PROMPT1("%8s  %-17llu  %-17llu  %-17llu  %-17llu\n"), "FLT BYTE", 
			(unsigned long long)stats->port[0].byt_filter - (unsigned long long)stats->port_base[0].byt_filter_base, 
			(unsigned long long)stats->port[1].byt_filter - (unsigned long long)stats->port_base[1].byt_filter_base, 
			(unsigned long long)stats->port[2].byt_filter - (unsigned long long)stats->port_base[2].byt_filter_base, 
			(unsigned long long)stats->port[3].byt_filter - (unsigned long long)stats->port_base[3].byt_filter_base);
	if ((cardtype&0x000fffff) == 0x82599) {
		printf(PROMPT1("%8s  %-17llu  %-17llu  %-17llu  %-17llu\n"), "OUT PKTS", 
				(unsigned long long)stats->port[0].pkt_outputs - (unsigned long long)stats->port_base[0].pkt_outputs_base,
				0ULL,
				(unsigned long long)stats->port[1].pkt_outputs - (unsigned long long)stats->port_base[1].pkt_outputs_base,
           0ULL);            
    printf(PROMPT1("%8s  %-17llu  %-17llu  %-17llu  %-17llu\n"), "OUT BYTE", 
           (unsigned long long)stats->port[0].byt_outputs - (unsigned long long)stats->port_base[0].byt_outputs_base,
           0ULL,
           (unsigned long long)stats->port[1].byt_outputs - (unsigned long long)stats->port_base[1].byt_outputs_base,
           0ULL);
    } else if ((cardtype&0x00000fff) == 0x710) {
        printf(PROMPT1("%8s  %-17llu  %-17llu  %-17llu  %-17llu\n"), "OUT PKTS", 
           (unsigned long long)stats->port[0].pkt_outputs - (unsigned long long)stats->port_base[0].pkt_outputs_base,
           (unsigned long long)stats->port[1].pkt_outputs - (unsigned long long)stats->port_base[1].pkt_outputs_base,
           (unsigned long long)stats->port[2].pkt_outputs - (unsigned long long)stats->port_base[2].pkt_outputs_base,
           (unsigned long long)stats->port[3].pkt_outputs - (unsigned long long)stats->port_base[3].pkt_outputs_base);            
        printf(PROMPT1("%8s  %-17llu  %-17llu  %-17llu  %-17llu\n"), "OUT BYTE", 
           (unsigned long long)stats->port[0].byt_outputs - (unsigned long long)stats->port_base[0].byt_outputs_base,
           (unsigned long long)stats->port[1].byt_outputs - (unsigned long long)stats->port_base[1].byt_outputs_base,
           (unsigned long long)stats->port[2].byt_outputs - (unsigned long long)stats->port_base[2].byt_outputs_base,
           (unsigned long long)stats->port[3].byt_outputs - (unsigned long long)stats->port_base[3].byt_outputs_base);
    } 
    printf(PROMPT1("------------------------------------------------------------------------------------\n\n"));
    
    return 0;
}


/*************************************************************************************
 *
 * SFP+ Module info
 *
 ************************************************************************************/
#define PRER_LO        (0x00)
#define PRER_HI        (0x01)
#define CTR            (0x02)
#define TXR            (0x03)
#define CR             (0x04)
#define RXR            (0x03)
#define SR             (0x04)
#define RD             (0x1)
#define WR             (0x0)
#define SFP_MSA_E2PROM (0xA0)
#define SFP_MSA_DIAG   (0xA2)

static int wb_write(uint8_t port, uint8_t addr, uint8_t data)
{
    unsigned int i2c_base;
    
    switch (port) {
    case 0: i2c_base = I2C_BASEADDR0; break;
    case 1: i2c_base = I2C_BASEADDR1; break;
    case 2: i2c_base = I2C_BASEADDR2; break;
    case 3: i2c_base = I2C_BASEADDR3; break;
    default: break;
    }
    reg_write(i2c_base, (0x80000000+addr*256+data));
    usleep(100);
    return 0;
}

static uint8_t wb_read(uint8_t port, uint8_t addr)
{
    unsigned int i2c_base;
    
    switch (port) {
    case 0: i2c_base = I2C_BASEADDR0; break;
    case 1: i2c_base = I2C_BASEADDR1; break;
    case 2: i2c_base = I2C_BASEADDR2; break;
    case 3: i2c_base = I2C_BASEADDR3; break;
    default: break;
    }
    reg_write(i2c_base, (addr*256));
    usleep(100);
    return reg_read(i2c_base);
}

static void wait_trans_done(uint8_t port)
{
    uint8_t q = 0;
    unsigned int timeout = 50;    
    
    if(port > 3)
        return ;
    q = wb_read(port, SR);
    while ((q & 0x2) && (timeout != 0)) {
        q = wb_read(port, SR);
        timeout--;
        usleep(100);
    }
}

static uint8_t i2c_random_read8(uint8_t port, uint8_t slave_addr, uint8_t mem_addr)
{
    uint8_t result = 0;
    
    if(port > 3) 
        return result;
    wb_write(port, TXR, slave_addr+WR);  /* drive slave address */
    wb_write(port, CR, 0x90);
    wait_trans_done(port);
    wb_write(port, TXR, mem_addr);       /* send memory address */
    wb_write(port, CR, 0x10);
    wait_trans_done(port);
    wb_write(port, TXR, slave_addr+RD);  /* drive slave address */
    wb_write(port, CR, 0x90);
    wait_trans_done(port);
    wb_write(port, CR, 0x28);            /* read data from slave */
    wait_trans_done(port);
    result = wb_read(port, RXR);
    wb_write(port, CR, 0x40);
    usleep(1);
    return result;
}

static void i2c_init(uint8_t port)
{
    if (port > 3)
        return ;
    wb_write(port, CTR,     0x0);  /* disable core */
    wb_write(port, PRER_LO, 0xc7); /* load prescaler lo-byte */
    wb_write(port, PRER_HI, 0x00); /* load prescaler hi-byte */
    wb_write(port, CTR,     0x80); /* enable core */
}

static double convert_mw_to_dbm(double mw)
{
    return (10.*log10(mw/1000.)) + 30.;
}

int get_module_status(uint8_t port, moduleinfo_t *info)
{
    int     i;
    uint8_t volt[2], power[2], temp[2], addr=20;
    
    for (i = 0; i < 16; i++,addr++) {
        info->vendor_name[i] = i2c_random_read8(port, SFP_MSA_E2PROM, addr);
    }
    info->vendor_name[i] = '\0';
    
    memset(temp, 0, 2);
    memset(volt, 0, 2);
    memset(power, 0, 2);
    temp[0]  = i2c_random_read8(port,SFP_MSA_DIAG,96);
    temp[1]  = i2c_random_read8(port,SFP_MSA_DIAG,97);
    volt[0]  = i2c_random_read8(port,SFP_MSA_DIAG,98);
    volt[1]  = i2c_random_read8(port,SFP_MSA_DIAG,99);
    power[0] = i2c_random_read8(port,SFP_MSA_DIAG,104);
    power[1] = i2c_random_read8(port,SFP_MSA_DIAG,105);
    sprintf(info->power, "%.2f", convert_mw_to_dbm((double)(((power[0] << 8)|power[1])/10000.)));
    sprintf(info->temp, "%.2f", (double)(((temp[0] << 8)|temp[1])/256.));
    sprintf(info->volt, "%.4f", (double)(((volt[0] << 8)|volt[1])/10000.));
    return 0;
}

static int show_module_info()
{
    moduleinfo_t info;
    int          i;
    
    if (i2c_inited == 0) {
        for (i = 0; i < 4; i++)
            i2c_init(i);
        i2c_inited = 1;
    }
    
    printf(PROMPT1("%4s  %-15s  %-11s  %-11s  %-11s\n"), "PORT", "Vendor", "Temp", "Power", "Volt");
    printf(PROMPT1("----------------------------------------------------------------\n"));
    for (i = 0; i < 4; i++) {
        memset(&info, 0, sizeof(moduleinfo_t));
        get_module_status(i, &info);
        printf(PROMPT1("%4d  %-15s  %-11s  %-11s  %-11s\n"), (i+1), 
               info.vendor_name, info.temp, info.power, info.volt);
    }
    printf(PROMPT1("----------------------------------------------------------------\n\n"));
    return 0;
}


/*************************************************************************************
 *
 * Main
 *
 ************************************************************************************/
int main(int argc, char **argv)
{
    int       menu, c, errflag = 0;
    uint32_t  addr, value;
    char      **spp;
    
    while ((c = getopt_long(argc, argv, "Df:V?", longopts, 0)) != EOF)
        switch (c) {
        case 'D': debug++; break;
        case 'f': opt_f++; strcpy(opt_FileName, optarg); break;
        case 'V': opt_version++; break;
        case '?': errflag++;
	}
    if (errflag) {
        printf(PROMPT1("\n"));
        printf(PROMPT1("%s\n"), usage_msg);
        return 2;
    }
    if (opt_version) {
        printf(PROMPT1("\n"));
        printf(PROMPT1("%s\n"), version);
        return 2;
    }
    if (optind == argc) {
        strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);
        printf(PROMPT1("\n"));
        printf(PROMPT1("Using the default interface 'eth0'.\n"));
    } else {
        spp = argv + optind;
        strncpy(ifr.ifr_name, *spp++, IFNAMSIZ);
    }
    /* printf("ifr.ifr_name is: %s\n", ifr.ifr_name); */
    
    if (opt_f == 0)
        printf(PROMPT1("Using the default filter rules 'filter.rules'.\n"));
    
    if ((skfd = socket(AF_INET, SOCK_DGRAM,0)) < 0) {
        printf(PROMPT1("Open Socket Failed!\n"));
		return -1;
	}

    fpga_stats_t  *stats;
	stats	= (fpga_stats_t *)malloc ( sizeof(fpga_stats_t) );
	if ( stats==NULL ) {
		fprintf ( stderr, "\ndynamic memory allocation failed\n" );
		exit (EXIT_FAILURE);
	}
	fpga_statistics_base_init(&stats);
	if (debug) {
		while (1) {
			printf(PROMPT1("\n\n"));
			printf(PROMPT1("****************************************\n"));
			printf(PROMPT1("1: Verify Filter Rules\n"));
			printf(PROMPT1("2: Install Filter Rules\n"));
			printf(PROMPT1("3: Remove Filter Rules\n"));
			printf(PROMPT1("4: Show Sfp+ Module infomation\n"));
			printf(PROMPT1("5: Show FPGA Statistics\n"));
			printf(PROMPT1("6: clear FPGA Statistics\n"));
			printf(PROMPT1("7: Write FPGA Register\n"));
			printf(PROMPT1("8: Read FPGA Register\n"));
			printf(PROMPT1("9: Write MDIO Register\n"));
			printf(PROMPT1("10: Read MDIO Register\n"));
			printf(PROMPT1("11: Exit \n"));
			printf(PROMPT1("****************************************\n\n"));
			scanf("%d",&menu);
			getchar();
			if(menu > 11 || menu < 1)
			{
				printf("please input 1-10 number!!\n");
				continue;
			}
			switch (menu) {
				case 1: 
					verify_only = 1;
                rules_install();
                break;
            case 2:
                verify_only = 0;
                rules_install();
                break;
			case 3: 
				rules_remove();
				break;
            case 4:
                show_module_info();
                break;
			case 5:
				show_fpga_statistics(&stats);
				break;
			case 6:
				fpga_statistics_base(&stats); 
				printf("clear success!\n");
				break;
			case 7:
				printf(PROMPT1("Input Register Address:            "));
				scanf("%x", &addr);
				printf(PROMPT1("Input Register Value:              "));
				scanf("%x", &value);
				reg_write(addr, value);
				break;
			case 8:
				printf(PROMPT1("Input Register Address:            "));
				scanf("%x", &addr);
				printf(PROMPT1("Register Value is:                 0x%x\n"), reg_read(addr));
				break;
			case 9:
				printf(PROMPT1("Input MDIO Register Address:       "));
                scanf("%x", &addr);
                printf(PROMPT1("Input MDIO Register Value:         "));
                scanf("%x", &value);
                mdio_write((uint16_t)addr, (uint16_t)value);
                break;
            case 10:
                printf(PROMPT1("Input MDIO Register Address:       "));
                scanf("%x", &addr);
                printf(PROMPT1("MDIO Register Value is:            0x%04x\n"), mdio_read((uint16_t)addr));
                break;
            default:
                goto end;
                break;
            }
        }
    } else    /* install rules directly */
        rules_install();
    
end:
    close(skfd);
    
    return 0;
}

/* End Of File */
