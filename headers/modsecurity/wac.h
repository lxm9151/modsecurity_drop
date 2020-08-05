#include <modsecurity/transaction.h>
#include <modsecurity/rules.h>
#include <modsecurity/rule.h>
#include <hiredis/hiredis.h>

#include <yajl/yajl_parse.h>

#ifdef __cplusplus
#include <string>
#include <iostream>
#include <deque>
//using namespace std;
using namespace modsecurity;
namespace modsecurity {

 class ModSecurity;
 class Transaction;
 class Rules;
 class RuleMessage;
 namespace actions {
 class Action;
 namespace disruptive {
 enum AllowType : int;
 }
 }
 namespace RequestBodyProcessor {
 class XML;
 class JSON;
 }
 namespace operators {
 class Operator;
 }
}

#endif


#ifndef WAC_H
#define WAC_H
#ifndef __cplusplus
typedef struct WAC_t WAC;
#endif

#define ENABLE_URIC(x) x|=0x01
#define DISABLE_URIC(x) x&=0xFE
#define ENABLE_PASS(x) x|=0x02
#define DISABLE_PASS(x) x&=0xFD
#define ALLOW_METHOD_GET(x) x&0x01
#define ALLOW_METHOD_POST(x) x&0x02
#define SET_METHOD_GET(x) x|=0x01
#define SET_METHOD_POST(x) x|=0x02
//#define SET_CON_OPTION(x) x|=0x01
//#define ALLOW_CON_OPTION(x) x&0x01
//#define SET_CON_MULTI(x) x|=0x02
//#define ALLOW_CON_MULTI(x) x&0x02
#define SET_CONTYPE_BIN(x) x|=0x02
#define ALLOW_CONTYPE_BIN(x) x&0x02
#define SET_CONTYPE_SP(x) x|=0x04 /* 包括空格 \t \n \r */
#define ALLOW_CONTYPE_SP(x) x&0x04 /* 包括空格 \t \n \r */
#define SET_CONTYPE_SENS(x) x|=0x08 /* 包括空格 * . ; {} */
#define ALLOW_CONTYPE_SENS(x) x&0x08 /* 包括空格 * . ; {} */
#define SET_CONTYPE_RESERV(x) x|=0x10 /* 包括空格 * . ; {} */
#define ALLOW_CONTYPE_RESERV(x) x&0x10 /* 包括空格 * . ; {} */

#define SET_DATATYPE_NUMBER(x) x|=0x01
#define ALLOW_DATATYPE_NUMBER(x) x&0x01
#define SET_DATATYPE_STRING(x) x|=0x02
#define ALLOW_DATATYPE_STRING(x) x&0x02
#define SET_DATATYPE_OBJECT(x) x|=0x04
#define ALLOW_DATATYPE_OBJECT(x) x&0x04
#define SET_DATATYPE_ARRAY(x) x|=0x08
#define ALLOW_DATATYPE_ARRAY(x) x&0x08

#define SET_ARRAYTYPE_NUMBER(x) x|=0x01
#define ALLOW_ARRAYTYPE_NUMBER(x) x&0x01
#define SET_ARRAYTYPE_STRING(x) x|=0x02
#define ALLOW_ARRAYTYPE_STRING(x) x&0x02
#define SET_ARRAYTYPE_OBJECT(x) x|=0x04
#define ALLOW_ARRAYTYPE_OBJECT(x) x&0x04
#define SET_ARRAYTYPE_ARRAY(x) x|=0x08
#define ALLOW_ARRAYTYPE_ARRAY(x) x&0x08

#define SET_SENS_MAP(x,y) x|=1<<y
#define CLR_SENS_MAP(x,y) x&=(!(1<<y))

#define PATTERN_LEN 200

#define WAC_OFF 0
#define WAC_ON 1
#define WAC_DETECTONLY 2
#define WAC_STUDYONLY 3

#define WAC_WHITE 1
#define WAC_BLACK 2

extern
#ifdef __cplusplus
"C" 
#endif
 redisContext *redisConn;

#ifdef __cplusplus

struct ArgDiff {
    unsigned char exist; /* 0, 1新增,2缺失 */
    unsigned char arrayType; /* 数组元素数据类型 */
    unsigned char dataType; 
    unsigned char conType; /*  option,允许多值,允许二进制，允许空格，允许敏感字符 */
    short maxCnt; /* 多值、对象类型或数组类型允许的最多值数 */
    float maxLength; /* 原生或数组类型允许的最大长度 */
    char riskLevel;
};

class ArgCharact {
    public:
        ArgCharact();
        ~ArgCharact();

        void parseValue(const std::string& value);
        void merg(ArgCharact *src);

    public:
        unsigned char m_arrayType; /* 数组元素数据类型 */
        unsigned char m_dataType; 
        unsigned char m_conType; /*  option,允许多值,允许二进制，允许空格，允许敏感字符 */
        short m_maxCnt; /* 多值、对象类型或数组类型允许的最多值数 */
        short m_maxLength; /* 原生或数组类型允许的最大长度 */
        float m_reservedRate;
        char m_riskLevel;
};

class WAC {
    public:
        WAC();
        //WAC(string uri);
        ~WAC();

        void init(modsecurity::Transaction *t);
        void merg(WAC* src);
        //int detect(int whiteLevel,int blackLevel);
        int detect();
        //void save(int blackLevel);
        void save();
        std::string auditLog(int format,int part);
    private:
        void load();
        
    public:
//增加风险等级，1级数值或文本，文本没有空格\n\t等字符，2级有特殊字符或二进制，3级符合语言特征
        char m_riskLevel;
        std::string m_uri;
        bool m_needStudy; /* bit 0 特性规则控制 */
        std::map<std::string,std::set<std::string>*> m_heads; /* name,可选值 */
        unsigned char m_method; /* bit 0 get,bit 1 post */
        unsigned char m_bodyType; /* formdata/json/xml */
        std::map<std::string,ArgCharact*> m_argCharacts; /* json的root node name 为"/" 子节点用“/”分隔 */
        WAC *m_savedWAC;
        modsecurity::Transaction* m_transaction;

        bool m_new; 
        unsigned char m_method_diff;
        unsigned char m_bodyType_diff;
        char m_riskLevel_diff;
        std::map<std::string,ArgDiff*> m_arg_diffs; 
};

class CJSONContainer {
 public:
    explicit CJSONContainer(std::string name)
        : m_name(name),
        m_argCharact(new ArgCharact()),
        m_elementCounter(0) 
    { 
    }

    virtual ~CJSONContainer() { 
//        delete m_argCharact;
    }

    std::string m_name;
    ArgCharact *m_argCharact;
    size_t m_elementCounter;
};


class CJSONContainerArray : public CJSONContainer {
 public:
    explicit CJSONContainerArray(std::string name) : CJSONContainer(name)
         { SET_DATATYPE_ARRAY(m_argCharact->m_dataType);}
};


class CJSONContainerMap : public CJSONContainer {
 public:
     explicit CJSONContainerMap(std::string name) : CJSONContainer(name)
         { SET_DATATYPE_OBJECT(m_argCharact->m_dataType);}
};


class CJSON {
 public:
    explicit CJSON(WAC *pWac);
    ~CJSON();

    bool init();
    bool processChunk(const char *buf, unsigned int size, std::string *err);
    bool complete(std::string *err);

    int addArgument(const std::string& value);
    int addObject();

    static int yajl_number(void *ctx, const char *value, size_t length);
    static int yajl_string(void *ctx, const unsigned char *value,
        size_t length);
    static int yajl_boolean(void *ctx, int value);
    static int yajl_null(void *ctx);
    static int yajl_map_key(void *ctx, const unsigned char *key,
        size_t length);
    static int yajl_end_map(void *ctx);
    static int yajl_start_map(void *ctx);
    static int yajl_start_array(void *ctx);
    static int yajl_end_array(void *ctx);

    bool isPreviousArray() {
        CJSONContainerArray *prev = NULL;
        if (m_containers.size() < 1) {
            return false;
        }
        prev = dynamic_cast<CJSONContainerArray *>(
            m_containers[m_containers.size() - 1]);
        return prev != NULL;
    }

    std::string getCurrentKey(bool emptyIsNull = false) {
        std::string ret(m_current_key);
        if (m_containers.size() == 0) {
            return "J:";
        }
        if (m_current_key.empty() == true) {
            if (isPreviousArray() || emptyIsNull == true) {
                return "";
            }
            return "empty-key";
        }
        m_current_key = "";
        return ret;
    }

 private:
    std::deque<CJSONContainer *> m_containers;
    //Transaction *m_transaction;
    WAC *m_wac;
    yajl_handle m_handle;
    yajl_status m_status;
    std::string m_current_key;
};
#endif

#ifdef __cplusplus
extern "C" {
#endif

   WAC* wac_create(Transaction *t);
   //int wac_detect(WAC* pWAC,int whiteLevel,int blackLevel);
   int wac_detect(WAC* pWAC);
   //void wac_study(WAC* pWAC,int blackLevel);
   void wac_study(WAC* pWAC);
   void wac_free(WAC* pWAC);

#ifdef __cplusplus
}
#endif

#endif
