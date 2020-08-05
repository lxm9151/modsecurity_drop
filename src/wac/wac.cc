#include "modsecurity/wac.h"
//#include "wac.h"
#include <iostream>
#include <cstring>
#include <deque>

#include <list>
#include <string>

#include <stdio.h>
#include <string.h>
//#include <hiredis/hiredis.h>
using namespace std;
using namespace modsecurity;

redisContext * redisConn;

const set<string> reservedSet(
        {
        // SQL
        "select",
        "insert",
        "delete",
        "truncate",
        "drop",
        "alter",
        "from",
        "into",
        "where",
        "like",
        "and",
        "or",
        "between",
        "union",
        "case",
        "when",
//        "all",
//        "any",
        "table",
        "database",
        // js
//        "script",
        "alert",
        "cookie",
//        "document",
        "abstract",
       "arguments",
      "boolean",
"break",
"byte",
"catch",
"char",
"class",
"const",
//"continue",
"debugger",
//"default",
//"do",
"double",
"else",
"enum",
"eval",
//"export",
"extends",
"false",
"final",
"finally",
"float",
//"for",
"function",
"goto",
"if",
"implements",
//"import",
//"in",
"instanceof",
"int",
"interface",
//"let",
"long",
"native",
"true",
"void",
"null",
"yield",
"foreach",
"var",
"return",
"lambda",
"def",
    "elif",
//    "none",
    "try",
    "catch",
    "while",
//    "do",
//    "done",
    "fi",
    "throw",
    "then",
    "esac",
    "exec",
//    "exit",
    "until",
    "alias",
    "rm",
    "cp",
    "tar",
    "cd",
    "ls",
    "ps",
    "mv",
    "cat",
    "xargc",
    "awk",
    "bool",
    "http",
    "https",
    "mail",
    "ftp",
    "file",
    "ssh",
    "scp"
        }
        );

inline int sensPos(char *c){
    switch(*c){
        case '!':
            return 0;
        case '$':
            return 1;
        case '%':
            return 2;
        case '&':
            return 3;
        case '(':
            return 4;
        case ')':
            return 5;
        case '*':
            return 6;
        case '+':
            return 7;
        case '-':
            return 8;
        case '.':
            return 9;
        case '/':
            return 10;
        case '<':
            return 11;
        case '=':
            return 12;
        case '>':
            return 13;
        case '?':
            return 14;
        case '[':
            return 15;
        case ']':
            return 16;
        case '\\':
            return 17;
        case '^':
            return 18;
        case '{':
            return 19;
        case '}':
            return 20;
        case '|':
            return 21;
        case '~':
            return 22;
        case '`':
            return 23;
        case '"':
            return 24;
        case '\'':
            return 25;
        case ',':
            return 26;
        case ';':
            return 27;
        case ':':
            return 28;
        case '#':
            return 29;
        case '@':
            return 30;
        default:
            return -1;
    }
}

inline bool isSens(char *c){
        if(
        *c== '!' ||
        *c== '$' ||
        *c== '%' ||
        *c== '&' ||
        *c== '(' ||
        *c== ')' ||
        *c== '*' ||
        *c== '+' ||
        *c== '-' ||
        *c== '.' ||
        *c== '/' ||
        *c== '<' ||
        *c== '=' ||
        *c== '>' ||
        *c== '?' ||
        *c== '[' ||
        *c== ']' ||
        *c== '\\' ||
        *c== '^' ||
        *c== '{' ||
        *c== '}' ||
        *c== '|' ||
        *c== '~' ||
        *c== '`' ||
        *c== '"' ||
        *c== '\'' ||
        *c== ',' ||
        *c== ';' ||
        *c== ':' ||
        *c== '#' ||
        *c== '@' 
        ) return true;
        return false;
}

inline bool isSp(char *c){
        if(*c==' '||*c=='\t'||*c=='\n'||*c=='\r') return true;
        return false;
}

inline bool isPun(char *c){
        //if(*c==','||*c==';'||*c==':'||*c=='\''||*c=='"'||*c=='#'||*c=='@') return true;
        return false;
}

inline bool isDig(char *c){
    if(*c>='0' && *c<='9') return true;
    return false;
}

inline bool isChar(char *c){
    if(*c>='A' && *c<='Z' || *c>='a' && *c<='z' ||*c=='_') return true;
    return false;
}

inline bool isReserved(const char* word){
    set<string>::iterator iter;
     if((iter = reservedSet.find(word)) != reservedSet.end()){

         return true;
     }
     return false;
}

inline bool isNum(const string& s)
{
        stringstream sin(s);
        double d;
        char c;
        if(!(sin >> d))
               return false;
        if(sin >> c)
                return false;
        else
                return true;
}

double parsePattern( char * pat){
    char *begin,*end;
    char ss[11];
    unsigned int mm=0;
    int cc=0;
    int ll=0;
    int i=0;
    double maxRisk;
    double risk;

    if(*pat==0){
        return 0;
    }

    begin=pat;
    end=begin+strlen(pat);
    while(*end=='.'){
        end=0;
        end--;
    }

    if(end-begin<3){
        return 0;
    }
    if(end-begin==3 && *begin==*(begin+2) && ( *begin=='\'' || *begin=='"')){
        return 0;
    }

    do{
        ll=end-begin;
        if(ll>10){
            ll=10;
        }
        mm=0;
        cc=0;
        memset(ss,0,sizeof(ss));
        strncpy(ss,begin,10);
        for(i=0; *begin!=0 && i<ll ;i++){
            if(isSens(begin+i)){
                int pos=sensPos(begin+i);

                if(pos>=0){
                    SET_SENS_MAP(mm,pos);
                }
            }
            if(*(begin+i)=='R'){
                cc++;
            }
        }

        for(int j=0;j<32;j++){
            if(mm&(1<<j)){
                cc++;
            }
        }

        risk=(double)cc/ll;
        if(risk<0.3 || risk >0.9){
            risk=0;
        }
        //////////////////
        else{
            break;
        }
        //////////////////
        begin++;

    } while(end-begin>=10);

    if(risk>maxRisk){
        maxRisk=risk;
    }


    return maxRisk*100;

}

typedef struct ArgCharactMem {
    char name[200];
    unsigned char m_arrayType;
    unsigned char m_dataType;
    unsigned char m_conType;
    short m_maxCnt;
    short m_maxLength;
    char m_riskLevel;
} ArgCharactMem_t;

typedef struct WACMem {
    unsigned char m_method;
    unsigned char m_bodyType;
    char m_riskLevel;
} WACMem_t;

ArgCharact::ArgCharact()
    :m_arrayType(0),
    m_dataType(0),
    m_conType(0),
    m_maxLength(0),
    m_riskLevel(0)
{
}

ArgCharact::~ArgCharact(){}

inline void setPattern(unsigned char c,char *pattern,int &patPos){ 

        if(pattern[patPos]==0 && c!='S'){ 
            pattern[patPos]= c; 
            return;
        }    
        if(c=='C'){
            if(c!=pattern[patPos] && pattern[patPos]!='Z'){
                patPos++;
                pattern[patPos]= c; 
            }
            return;
        }
        if(c=='R'){
            pattern[patPos]= c; 
            return;
        }
        if(c=='Z'){
            if(c!=pattern[patPos]){
                if(pattern[patPos]!='C'){
                    patPos++;
                }
                pattern[patPos]= c; 
            }
            return;
        }
        if(c=='D'){
            if(c!=pattern[patPos] && pattern[patPos]!='C' && pattern[patPos]!='Z'){
                patPos++;
                pattern[patPos]= c; 
            }
            return;
        }
        if(c=='S'){
            if(pattern[patPos]){
                patPos++;
            }
            return;
        }
        
        patPos++;
        pattern[patPos]=c;
        return;
}

/* 风险等级评定：
 * 空格 1分；敏感字符每种 1分；关键字 占比1/3以上 1分
 * 风险系数为以上分数相加 0分低风险 1分中等风险 2分及以上为高风险
 * 中低风险可以认为是白名单放行，高风险需送modsscurity验证或直接拦截
 */


void ArgCharact::parseValue(const string& value){

    char pattern[PATTERN_LEN];
    memset(pattern,0,sizeof(pattern));

    m_maxCnt=1;

    if(isNum(value)){
        SET_DATATYPE_NUMBER(m_dataType);
        m_maxLength=0;

        return;
    }
    else{

        char* ws=NULL;
        int wsInd=-1; // -1 未定义，0 数字，1 字符

        int patPos=0;

        SET_DATATYPE_STRING(m_dataType);
        m_maxLength=value.length();

        char *begin,*end,*p;

        begin=(char*)value.c_str();
        while(isSp(begin) && *begin!=0){
            begin++;
        }
        end=begin+strlen(begin)-1;
        while(isSp(end) && end>=begin){
            end--;
        }
        end++;
        *end=0;
        
        p=begin;
        while(p<end){
            if(isSp(p)){
                SET_CONTYPE_SP(m_conType);
                if(ws){
                    if(wsInd==1){
                        char tc=*p;
                        *p=0;
                        //ws  判断关键字
                        if(isReserved(ws)){
                            setPattern('R',pattern,patPos);
                        }
                        *p=tc;
                    }
                    ws=NULL;
                    wsInd=-1;
                }
                setPattern('S',pattern,patPos);
            }
            else if(isSens(p)) {
                if(ws){
                    if(wsInd==1){
                        char tc=*p;
                        *p=0;
                        if(isReserved(ws)){
                            setPattern('R',pattern,patPos);
                        }   
                        *p=tc;
                    }
                    ws=NULL;
                    wsInd=-1;
                }
                setPattern(*p,pattern,patPos);
            }
            else if(isPun(p)){
                if(ws){
                    if(wsInd==1){
                        char tc=*p;
                        *p=0;
                        //ws  判断关键字
                        if(isReserved(ws)){
                            setPattern('R',pattern,patPos);
                        }
                        *p=tc;
                    }
                }
                ws=NULL;
                wsInd=-1;
                setPattern(*p,pattern,patPos);
            }
            else if(isDig(p)){
                if(ws){
                    if(wsInd!=0){
                        wsInd=2;
                    }
                }
                else{
                    ws=p;
                    wsInd=0;
                }
                setPattern('D',pattern,patPos);
            }
            else if(isChar(p)){
                *p=tolower(*p);
                if(ws){
                    if(wsInd!=1){
                        wsInd=2;
                    }
                }
                else{
                    ws=p;
                    wsInd=1;
                }
                setPattern('C',pattern,patPos);
            }
            else if((unsigned char)*p>127) { //中文
                if(ws){
                        wsInd=2;
                }
                else{
                    ws=p;
                    wsInd=2;
                }
                int l=0;
                while(*p&0x80>>l){
                    l++;
                }
                p+=l-1;
                setPattern('Z',pattern,patPos);
            }
            else{

                SET_CONTYPE_BIN(m_conType);
                m_riskLevel=1; //含二进制设置固定风险系数
                return;
            }

            p++;
        }

        if(ws && wsInd==1){
            if(isReserved(ws)){
                setPattern('R',pattern,patPos);
            }
        }

        if(parsePattern(pattern)>0){
            m_riskLevel=1;
        }
        else{
            m_riskLevel=0;
        }

    }
}

void ArgCharact::merg(ArgCharact *src){
    //m_maxCnt++;
    m_dataType|=src->m_dataType;
    m_conType|=src->m_conType;
    if(m_maxLength<src->m_maxLength){
        m_maxLength=src->m_maxLength;
    }
    if(m_riskLevel<src->m_riskLevel){
        m_riskLevel=src->m_riskLevel;
    }
}

WAC::WAC()
    :m_riskLevel(0),
    m_needStudy(true),
    m_bodyType(0),
    m_method(0),
    //m_wb(0),
    m_savedWAC(NULL)
{
}
/****
WAC::WAC(string uri)
    :m_uri(uri),
    m_riskLevel(0),
    m_needStudy(true),
    m_savedWAC(NULL)
{
}
*****/

WAC::~WAC()
{
    for(const auto& i: m_argCharacts){
        delete i.second;
    }
    for(const auto& i: m_heads){
        delete i.second;
    }
    if(m_savedWAC){
        delete m_savedWAC;
    }
    for(const auto& i: m_arg_diffs){
        delete i.second;
    }
    m_transaction=NULL;
}


void WAC::init(Transaction *t)
{
    m_savedWAC=new WAC();
    m_uri.assign(t->m_variablePathInfo.m_value);
    m_savedWAC->m_uri.assign(t->m_variablePathInfo.m_value);
    m_transaction=t;

    m_method=0;
    if(t->m_variableRequestMethod.m_value=="GET"){
        SET_METHOD_GET(m_method);
    }
    else if(t->m_variableRequestMethod.m_value=="POST"){
        SET_METHOD_POST(m_method);
    }


	std::vector<const modsecurity::VariableValue *> vv;
	t->m_variableRequestHeaders.resolve(&vv);
    for(const auto &i :vv){
	        map<string, set<string>*>::iterator it_find;
            string key=i->getKey();
            transform(key.begin(), key.end(), key.begin(), ::tolower);  

            if(key=="content-type"){
                if(i->getValue().find("json")!= i->getValue().npos ){
                    m_bodyType=1 ; //json
                }
                else if( i->getValue().find("xml")!= i->getValue().npos ){
                    m_bodyType=2 ; //xml
                }
                else {
                    m_bodyType=0 ; //formdata
                }
            }

	        it_find = m_heads.find(key);
	        if (it_find == m_heads.end()) {
                set<string> *ps=new set<string>();
                ps->insert(i->getValue());
	            m_heads.insert(pair<string,set<string>*>(key,ps));
	        }
	        else{
                it_find->second->insert(i->getValue());
	        }
    }

    if(m_bodyType==0){ //formdata
	    std::vector<const modsecurity::VariableValue *> vv;
	    t->m_variableArgs.resolve(&vv);
	    for (const auto& i : vv) {
            ArgCharact *pArgC=new ArgCharact();
            pArgC->parseValue(i->getValue());
	
	
	        map<string, ArgCharact*>::iterator it_find;
	        it_find = m_argCharacts.find(i->getKey());
	        if (it_find == m_argCharacts.end()) {
	            m_argCharacts.insert(pair<string,ArgCharact*>("KV:"+i->getKey(),pArgC));
	        }
	        else{
	            pArgC->merg(it_find->second);
                pArgC->m_maxCnt++;
	        }
	    }
    }

    else if(m_bodyType==1 ){ //json
        CJSON *cj=new CJSON(this);
        std::string error;
         if (cj->init() == true) {

             cj->processChunk(t->m_requestBody.str().c_str(),
                 t->m_requestBody.str().size(),
                 &error);
             cj->complete(&error);
         }
         if (error.empty() == false && t->m_requestBody.str().size() > 0) {
             t->m_variableReqbodyError.set("1", t->m_variableOffset);
             t->m_variableReqbodyProcessorError.set("1", t->m_variableOffset);
             t->m_variableReqbodyErrorMsg.set("JSON parsing error: " + error,
                 t->m_variableOffset);
             t->m_variableReqbodyProcessorErrorMsg.set("JSON parsing error: " \
                 + error, t->m_variableOffset);

             m_riskLevel=2;

         } else {
             t->m_variableReqbodyError.set("0", t->m_variableOffset);
             t->m_variableReqbodyProcessorError.set("0", t->m_variableOffset);
         }

    }
    else if(m_bodyType==2){ //xml
        fprintf(stderr,"xml body\n");
    } 

    for(const auto& i:m_argCharacts ){
        if(i.second->m_riskLevel>m_riskLevel){
            m_riskLevel=i.second->m_riskLevel;
        }
    }

    load();
}

extern "C" WAC* wac_create(Transaction *t){
    WAC* pWAC=new WAC();
    pWAC->init(t);
    return pWAC;
}

//extern "C" void wac_study(WAC* pWAC,int blackLevel){
extern "C" void wac_study(WAC* pWAC){
    if(pWAC->m_transaction->m_httpCodeReturned==200 
        ////////// for gansu sg app //////////////////
        || pWAC->m_transaction->m_httpCodeReturned==204
        ///////////////////////////////////////////////
        ){ //study
        fprintf(stderr,"------ WAC study uri:%s -----\n",pWAC->m_uri.c_str());
        pWAC->merg(pWAC->m_savedWAC);
        //pWAC->save(blackLevel);
        pWAC->save();
    }
}

//extern "C" int wac_detect(WAC* pWAC,int whiteLevel,int blackLevel){
extern "C" int wac_detect(WAC* pWAC){
        return pWAC->detect();
}

extern "C" void wac_free(WAC* pWAC){
    delete pWAC;
}

//int WAC::detect(int whiteLevel,int blackLevel)
int WAC::detect()
{
    redisReply *reply ;
    WAC* src=m_savedWAC;
    int ret;

    reply = (redisReply*)  redisCommand(redisConn, "get %s", src->m_uri.c_str());
    if(reply->str) {
        m_new=false;
        fprintf(stderr,"Match uri:%s\n",src->m_uri.c_str());
    }
    else{
        m_new=true;
        fprintf(stderr,"Did not match uri:%s\n",src->m_uri.c_str());
    }
    freeReplyObject(reply);
    m_method_diff=m_method|src->m_method;
    m_method_diff^=src->m_method;
    m_bodyType_diff=m_bodyType|src->m_bodyType;
    m_bodyType_diff^=src->m_bodyType;
    //m_argCount_diff=m_argCharacts.size()-src->m_argCharacts.size();
    m_riskLevel_diff=m_riskLevel-src->m_riskLevel;

    for(const auto &i:m_argCharacts){
        map<string, ArgCharact*>::iterator it_find;
        it_find = src->m_argCharacts.find(i.first);
        if (it_find == src->m_argCharacts.end()) {
            fprintf(stderr,"\tDid not match arg:%s\n",i.first.c_str());
            ArgDiff* pAcDiff=new ArgDiff();

            pAcDiff->exist=1;
            pAcDiff->arrayType=i.second->m_arrayType;
            pAcDiff->dataType=i.second->m_dataType;
            pAcDiff->conType=i.second->m_conType;
            pAcDiff->maxCnt=i.second->m_maxCnt;
            pAcDiff->maxLength=i.second->m_maxLength;
            pAcDiff->riskLevel=i.second->m_riskLevel;

            m_arg_diffs.insert(pair<string,ArgDiff*>(i.first,pAcDiff));

            //pWacDiff->argCount++;

            //pWacDiff->ac.insert(pair<string,AC_diff*>(i.first,pAcDiff));
        }      
        else{
            fprintf(stderr,"\tMatch arg:%s\n",i.first.c_str());
            ArgDiff* pAcDiff=new ArgDiff();

            pAcDiff->exist=0;
            pAcDiff->arrayType=i.second->m_arrayType|it_find->second->m_arrayType;
            pAcDiff->arrayType^=it_find->second->m_arrayType;
            pAcDiff->dataType=i.second->m_dataType|it_find->second->m_dataType;
            pAcDiff->dataType^=it_find->second->m_dataType;
            pAcDiff->conType=i.second->m_conType|it_find->second->m_conType;
            pAcDiff->conType^=it_find->second->m_conType;

            pAcDiff->maxCnt=i.second->m_maxCnt-it_find->second->m_maxCnt;
            pAcDiff->maxLength=1.0*i.second->m_maxLength-1.5*it_find->second->m_maxLength;
            pAcDiff->riskLevel=i.second->m_riskLevel-it_find->second->m_riskLevel;

            if(pAcDiff->arrayType || 
                    pAcDiff->dataType ||
                    pAcDiff->conType ||
                    pAcDiff->maxCnt >0 ||
                    pAcDiff->riskLevel >0 ||
                    pAcDiff->maxLength >0 ){

                m_arg_diffs.insert(pair<string,ArgDiff*>(i.first,pAcDiff));

                //pWacDiff->ac.insert(pair<string,AC_diff*>(i.first,pAcDiff));
            }
            else{
                delete pAcDiff;
            }
        }
    }


    if( m_new ||
            m_method_diff ||
            m_bodyType_diff ||
            //m_argCount_diff >0 ||
            m_riskLevel_diff >0 ||
            m_arg_diffs.size()>0 ){
        /****
        if(m_riskLevel>=blackLevel){
            m_needStudy=false; 
            m_transaction->m_it.disruptive=true;
            m_transaction->m_it.status=403;
            m_transaction->m_it.log=strdup("wac black list deny!");
            //m_wb=WAC_BLACK;
        }
        else{
            m_needStudy=true; 
        }
        ****/
            m_needStudy=true; 
        ret=1;
    }
    else{
        m_needStudy=false; 
        /****
        if(m_riskLevel<=whiteLevel){
            m_transaction->m_secRuleEngine=modsecurity::Rules::DisabledRuleEngine;
            m_wb=WAC_WHITE;
        }
        ****/
        ret=0;
    }
    /****
	    m_transaction->addArgument("GET","-WAC-NEW-URI-",to_string(m_new),0);
	    m_transaction->addArgument("GET","-WAC-DIFF-",to_string(m_needStudy),0);
	    m_transaction->addArgument("GET","-WAC-RISKLEVEL-",to_string(m_riskLevel),0);
	    m_transaction->addArgument("GET","-WAC-SAVED-INFO-",this->auditLog(0,0),0);
	    m_transaction->addArgument("GET","-WAC-REQUEST-INFO-",this->auditLog(0,1),0);
	    m_transaction->addArgument("GET","-WAC-DIFF-INFO-",this->auditLog(0,2),0);
        *****/
	    m_transaction->m_collections.m_tx_collection->storeOrUpdateFirst("_WAC_NEW",to_string(m_new));
	    //m_transaction->m_collections.m_tx_collection->storeOrUpdateFirst("_WAC_DEFF",to_string(m_method_diff || m_bodyType_diff || m_arg_diffs.size()>0 ));
	    m_transaction->m_collections.m_tx_collection->storeOrUpdateFirst("_WAC_DEFF",to_string(m_needStudy ));
	    m_transaction->m_collections.m_tx_collection->storeOrUpdateFirst("_WAC_RISKLEVEL",to_string(m_riskLevel));
	    m_transaction->m_collections.m_tx_collection->storeOrUpdateFirst("_WAC_SAVED",this->auditLog(0,0));
	    m_transaction->m_collections.m_tx_collection->storeOrUpdateFirst("_WAC_REQUEST",this->auditLog(0,1));
	    m_transaction->m_collections.m_tx_collection->storeOrUpdateFirst("_WAC_DIFF_INFO",this->auditLog(0,2));
        /***
	    std::vector<const modsecurity::VariableValue *> vv;
	    m_transaction->m_variableArgs.resolve(&vv);
	    for (const auto& i : vv) {
            fprintf(stderr,"11111111 %s,%s,%d\n",i->getKey().c_str(),i->getValue().c_str(),m_riskLevel);
	    }
        ***/

        return ret;
}

void WAC::merg(WAC *src)
{
    //m_ctrl|=src->m_ctrl;
    m_method|=src->m_method;
    m_bodyType|=src->m_bodyType;

    if(src->m_riskLevel>m_riskLevel){
        m_riskLevel=src->m_riskLevel;
    }

    for(const auto &i:src->m_argCharacts){

        map<string, ArgCharact*>::iterator it_find;
        it_find = m_argCharacts.find(i.first);
        if (it_find == m_argCharacts.end()) {
            ArgCharact* pArgC=new ArgCharact();
            memcpy(pArgC,i.second,sizeof(ArgCharact));
            m_argCharacts.insert(pair<string,ArgCharact*>(i.first,pArgC));
        }      
        else{
            it_find->second->merg(i.second);
        }
    }
}

void WAC::load()
{
    WACMem_t *pWac;
    redisReply *reply ;

    reply = (redisReply*)  redisCommand(redisConn, "get %s", m_uri.c_str());
    pWac=(WACMem_t*)reply->str;
    if(pWac){
        m_savedWAC->m_bodyType=pWac->m_bodyType;
        //m_savedWAC->m_ctrl=pWac->m_ctrl;
        m_savedWAC->m_method=pWac->m_method;
        m_savedWAC->m_riskLevel=pWac->m_riskLevel;
    }
    freeReplyObject(reply);

    reply = (redisReply*)redisCommand(redisConn,"lrange ARG[%s] 0 -1",m_uri.c_str());
    int j;
    if (reply->type == REDIS_REPLY_ARRAY) {
        for (j = 0; j < reply->elements; j++) {
            ArgCharactMem_t *pa;
            ArgCharact *pArgC=new ArgCharact();
            pa=(ArgCharactMem_t*)reply->element[j]->str;
            pArgC->m_maxCnt=pa->m_maxCnt;
            pArgC->m_conType=pa->m_conType;
            pArgC->m_arrayType=pa->m_arrayType;
            pArgC->m_dataType=pa->m_dataType;
            pArgC->m_maxLength=pa->m_maxLength;
            pArgC->m_riskLevel=pa->m_riskLevel;

	        m_savedWAC->m_argCharacts.insert(pair<string,ArgCharact*>(pa->name,pArgC));
        }       
    }   
    freeReplyObject(reply);
}

//void WAC::save(int blackLevel)
void WAC::save()
{

    //if(!m_needStudy || m_riskLevel>=blackLevel){
    if(!m_needStudy){
        return;
    }

    ArgCharactMem_t acm;
    WACMem_t wacm;

    redisReply *reply ;

    wacm.m_bodyType=m_bodyType;
    //wacm.m_ctrl=m_ctrl;
    wacm.m_method=m_method;
    wacm.m_riskLevel=m_riskLevel;
    reply = (redisReply*)  redisCommand(redisConn, "del %s", m_uri.c_str());
    freeReplyObject(reply);
    reply = (redisReply*)  redisCommand(redisConn, "set %s %b", m_uri.c_str(),&wacm, (size_t) sizeof(wacm));
    freeReplyObject(reply);

    reply = (redisReply*)  redisCommand(redisConn, "del ARG[%s]", m_uri.c_str());
    freeReplyObject(reply);
    for(const auto &i: m_argCharacts){
        strcpy(acm.name,i.first.c_str());
        acm.m_maxCnt=i.second->m_maxCnt;
        acm.m_dataType=i.second->m_dataType;
        acm.m_arrayType=i.second->m_arrayType;
        acm.m_conType=i.second->m_conType;
        acm.m_maxLength=i.second->m_maxLength;
        acm.m_riskLevel=i.second->m_riskLevel;


        reply = (redisReply*)  redisCommand(redisConn, "lpush ARG[%s] %b", m_uri.c_str(),&acm, (size_t) sizeof(acm));
        freeReplyObject(reply);
    }

    reply = (redisReply*)redisCommand(redisConn,"lrange ARG[%s] 0 -1",m_uri.c_str());
    int j;
    if (reply->type == REDIS_REPLY_ARRAY) {
        for (j = 0; j < reply->elements; j++) {
            ArgCharactMem_t *p;
            p=(ArgCharactMem_t*)reply->element[j]->str;
            fprintf(stderr,"%u) %s: dataType(%u), arrayType(%u), maxCnt(%u), maxLength(%d), riskLevel(%d)\n", 
                    j, p->name,p->m_dataType,p->m_arrayType,p->m_maxCnt,p->m_maxLength,p->m_riskLevel);
        }       
    }   
    freeReplyObject(reply);

}

string WAC::auditLog(int format,int part){
     std::stringstream audit_log;

     if(format==0){ // ssylog
         if(part==0){ // saved
             if(!m_new){
                 audit_log<<"WAC: Saved Info. [uri \""<<m_uri<<"\"";
                 audit_log<<" method "<<(int)m_savedWAC->m_method<<"";
                 audit_log<<" body_type "<<(int)m_savedWAC->m_bodyType<<"";
                 audit_log<<" risk_level "<<(int)m_savedWAC->m_riskLevel<<"]";
                 audit_log<<" [arg_name data_type containt_type array_type max_cnt max_length risk_level]";
                 for(const auto &i : m_savedWAC->m_argCharacts){
                     audit_log<<" [\""<<i.first<<"\"";
                     audit_log<<" "<<(int)i.second->m_dataType<<"";
                     audit_log<<" "<<(int)i.second->m_conType<<"";
                     audit_log<<" "<<(int)i.second->m_arrayType<<"";
                     audit_log<<" "<<(int)i.second->m_maxCnt<<"";
                     audit_log<<" "<<(int)i.second->m_maxLength<<"";
                     audit_log<<" "<<(int)i.second->m_riskLevel<<"]";
                 }

             }
         }
         else if(part==1){ // request
                 audit_log<<"WAC: Request Info. [uri \""<<m_uri<<"\"";
                 audit_log<<" method "<<(int)m_method<<"";
                 audit_log<<" body_type "<<(int)m_bodyType<<"";
                 audit_log<<" risk_level "<<(int)m_riskLevel<<"]";
                 audit_log<<" [arg_name data_type containt_type array_type max_cnt max_length risk_level]";
                 for(const auto &i : m_argCharacts){
                     audit_log<<" [\""<<i.first<<"\"";
                     audit_log<<" "<<(int)i.second->m_dataType<<"";
                     audit_log<<" "<<(int)i.second->m_conType<<"";
                     audit_log<<" "<<(int)i.second->m_arrayType<<"";
                     audit_log<<" "<<(int)i.second->m_maxCnt<<"";
                     audit_log<<" "<<(int)i.second->m_maxLength<<"";
                     audit_log<<" "<<(int)i.second->m_riskLevel<<"]";
                 }
         }
         else if(part==2){ //diff & action
             if(m_needStudy){
                 audit_log<<"WAC: Diff Info. [uri \""<<m_uri<<"\"";
                 audit_log<<" method "<<(int)m_method_diff<<"";
                 audit_log<<" body_type "<<(int)m_bodyType_diff<<"";
                 audit_log<<" risk_level "<<(int)m_riskLevel_diff<<"]";
                 audit_log<<" [arg_name existed data_type containt_type array_type max_cnt max_length risk_level]";
                 for(const auto &i : m_arg_diffs){
                     audit_log<<" [\""<<i.first<<"\"";
                     audit_log<<" "<<(int)i.second->exist<<"";
                     audit_log<<" "<<(int)i.second->dataType<<"";
                     audit_log<<" "<<(int)i.second->conType<<"";
                     audit_log<<" "<<(int)i.second->arrayType<<"";
                     audit_log<<" "<<(int)i.second->maxCnt<<"";
                     audit_log<<" "<<(int)i.second->maxLength<<"";
                     audit_log<<" "<<(int)i.second->riskLevel<<"]";
                 }
             }

         }
     }
     else if(format==1){ //json
     }

     return audit_log.str();
}


CJSON::CJSON(WAC *pUriC) 
    : m_wac(pUriC),
    m_handle(NULL),
    m_current_key("") {
    /**
     * yajl callback functions
     * For more information on the function signatures and order, check
     * http://lloyd.github.com/yajl/yajl-1.0.12/structyajl__callbacks.html
     */

    /**
     * yajl configuration and callbacks
     */
    static yajl_callbacks callbacks = {
        yajl_null,
        yajl_boolean,
        NULL /* yajl_integer  */,
        NULL /* yajl_double */,
        yajl_number,
        yajl_string,
        yajl_start_map,
        yajl_map_key,
        yajl_end_map,
        yajl_start_array,
        yajl_end_array
    };


    /**
     * yajl initialization
     *
     * yajl_parser_config definition:
     * http://lloyd.github.io/yajl/yajl-2.0.1/yajl__parse_8h.html#aec816c5518264d2ac41c05469a0f986c
     *
     * TODO: make UTF8 validation optional, as it depends on Content-Encoding
     */
    m_handle = yajl_alloc(&callbacks, NULL, this);

    yajl_config(m_handle, yajl_allow_partial_values, 0);
}


CJSON::~CJSON() {
    while (m_containers.size() > 0) {
        CJSONContainer *a = m_containers.back();
        m_containers.pop_back();
        delete a;
    }
    yajl_free(m_handle);
}


bool CJSON::init() {
    return true;
}


bool CJSON::processChunk(const char *buf, unsigned int size, std::string *err) {
    /* Feed our parser and catch any errors */
    m_status = yajl_parse(m_handle,
        (const unsigned char *)buf, size);
    if (m_status != yajl_status_ok) {
        unsigned char *e = yajl_get_error(m_handle, 0,
            (const unsigned char *)buf, size);
        /* We need to free the yajl error message later, how to do this? */
        err->assign((const char *)e);
        yajl_free_error(m_handle, e);
        return false;
    }

    return true;
}


bool CJSON::complete(std::string *err) {
    /* Wrap up the parsing process */
    m_status = yajl_complete_parse(m_handle);
    if (m_status  != yajl_status_ok) {
        unsigned char *e = yajl_get_error(m_handle, 0, NULL, 0);
        /* We need to free the yajl error message later, how to do this? */
        err->assign((const char *)e);
        yajl_free_error(m_handle, e);
        return false;
    }

    return true;
}

/**
 * indType 0 原生类型
 *  1 对象类型
 *  2 数组类型
 **/
int CJSON::addArgument(const std::string& value) {
    std::string data("");
    std::string path;
    std::string key;


    for (size_t i =  0; i < m_containers.size(); i++) {
        CJSONContainerArray *a = dynamic_cast<CJSONContainerArray *>(
            m_containers[i]);
        path = path + m_containers[i]->m_name;
        if (a != NULL) {
            path = path + "[]";
        } else {
            path = path + "{}";
        }
    }

    CJSONContainer *c = m_containers.back();
    c->m_elementCounter++;

    CJSONContainerArray *a = dynamic_cast<CJSONContainerArray *>(c);
    ArgCharact *pArgC=new ArgCharact();
    pArgC->parseValue(value);
    if (!a) {
        data = getCurrentKey();
        key=path+data;

        map<string, ArgCharact*>::iterator it_find;
        it_find = m_wac->m_argCharacts.find(key);
        if (it_find == m_wac->m_argCharacts.end()) {
            ArgCharact* tmpArgC=new ArgCharact();
            memcpy(tmpArgC,pArgC,sizeof(ArgCharact));
           m_wac->m_argCharacts.insert(pair<string,ArgCharact*>(key,tmpArgC));
        }
        else{
           it_find->second->merg(pArgC);
           it_find->second->m_maxCnt++;
        }
    }

    c->m_argCharact->m_arrayType|=pArgC->m_dataType;
    if(pArgC->m_maxLength>c->m_argCharact->m_maxLength){
        c->m_argCharact->m_maxLength=pArgC->m_maxLength;
    }
    delete pArgC;
    return 1;
}

int CJSON::addObject(){
    std::string path;
    for (size_t i =  0; i < m_containers.size(); i++) {
        CJSONContainerArray *a = dynamic_cast<CJSONContainerArray *>(
            m_containers[i]);
        path = path + m_containers[i]->m_name;
        if (a != NULL) {
            path = path + "[]";
        } else {
            path = path + "{}";
        }
    }

    CJSONContainer *c = m_containers.back();
    CJSONContainerArray *a = dynamic_cast<CJSONContainerArray *>(c);
    if(a==NULL){
        SET_DATATYPE_ARRAY(c->m_argCharact->m_arrayType);
    }
    else{
        SET_DATATYPE_OBJECT(c->m_argCharact->m_arrayType);
    }

    c->m_argCharact->m_maxCnt=c->m_elementCounter;    
    m_wac->m_argCharacts.insert(pair<string,ArgCharact*>(path,c->m_argCharact));

    return 1;
}



/**
 * Callback for hash key values; we use those to define the variable names
 * under ARGS. Whenever we reach a new key, we update the current key value.
 */
int CJSON::yajl_map_key(void *ctx, const unsigned char *key, size_t length) {
    CJSON *tthis = reinterpret_cast<CJSON *>(ctx);
    std::string safe_key;

    /**
     * yajl does not provide us with null-terminated strings, but
     * rather expects us to copy the data from the key up to the
     * length informed; we create a standalone null-termined copy
     * in safe_key
     */
    safe_key.assign((const char *)key, length);

    tthis->m_current_key = safe_key;

    return 1;
}


/**
 * Callback for null values
 *
 */
int CJSON::yajl_null(void *ctx) {
    CJSON *tthis = reinterpret_cast<CJSON *>(ctx);
    return tthis->addArgument("");
}


/**
 * Callback for boolean values
 */
int CJSON::yajl_boolean(void *ctx, int value) {
    CJSON *tthis =  reinterpret_cast<CJSON *>(ctx);
    if (value) {
        return tthis->addArgument("true");
    }
    return tthis->addArgument("false");
}


/**
 * Callback for string values
 */
int CJSON::yajl_string(void *ctx, const unsigned char *value, size_t length) {
    CJSON *tthis = reinterpret_cast<CJSON *>(ctx);
    std::string v = std::string((const char*)value, length);
    return tthis->addArgument(v);
}


/**
 * Callback for numbers; YAJL can use separate callbacks for integers/longs and
 * float/double values, but since we are not interested in using the numeric
 * values here, we use a generic handler which uses numeric strings
 */
int CJSON::yajl_number(void *ctx, const char *value, size_t length) {
    CJSON *tthis = reinterpret_cast<CJSON *>(ctx);
    std::string v = std::string((const char*)value, length);
    return tthis->addArgument(v);
}


/**
 * Callback for a new hash, which indicates a new subtree, labeled as the
 * current argument name, is being created
 */
int CJSON::yajl_start_array(void *ctx) {
    CJSON *tthis = reinterpret_cast<CJSON *>(ctx);
    std::string name = tthis->getCurrentKey();
    tthis->m_containers.push_back(
        reinterpret_cast<CJSONContainer *>(new CJSONContainerArray(name)));
    return 1;
}


int CJSON::yajl_end_array(void *ctx) {
    CJSON *tthis = reinterpret_cast<CJSON *>(ctx);
    if (tthis->m_containers.size() > 0) {
        CJSONContainer *c = (CJSONContainer *)(
            tthis->m_containers.back());
        tthis->addObject();
        tthis->m_containers.pop_back();
        delete c;
    }
    if (tthis->m_containers.size() > 0) {
        CJSONContainer *c = (CJSONContainer *)(
            tthis->m_containers.back());
            c->m_elementCounter++;
    }

    return 1;
}


int CJSON::yajl_start_map(void *ctx) {
    CJSON *tthis = reinterpret_cast<CJSON *>(ctx);
    std::string name(tthis->getCurrentKey());
    tthis->m_containers.push_back(
        reinterpret_cast<CJSONContainer *>(new CJSONContainerMap(name)));
    return 1;
}


/**
 * Callback for end hash, meaning the current subtree is being closed, and that
 * we should go back to the parent variable label
 */
int CJSON::yajl_end_map(void *ctx) {
    CJSON *tthis = reinterpret_cast<CJSON *>(ctx);

    if (tthis->m_containers.size() > 0) {
        CJSONContainer *c = (CJSONContainer *)(
            tthis->m_containers.back());
        tthis->addObject();
        tthis->m_containers.pop_back();
        delete c;
    }
    if (tthis->m_containers.size() > 0) {
        CJSONContainer *c = (CJSONContainer *)(
            tthis->m_containers.back());
            c->m_elementCounter++;
    }

    return 1;
}

