/* omhttps.c
 * Send all output to REST web service via http/https 
 *
 * Author: sskaje (sskaje@gmail.com, http://sskaje.me/)
 * Modifications for http/https: rdoctor(rdoctor@cisco.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "config.h"
#include "rsyslog.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <curl/curl.h>
#include <json.h>
#include <json_object.h>

#include "conf.h"
#include "syslogd-types.h"
#include "srUtils.h"
#include "template.h"
#include "module-template.h"
#include "errmsg.h"
#include "cfsysline.h"
#include "datetime.h"
#include "statsobj.h"
#include "unicode-helper.h"

MODULE_TYPE_OUTPUT
MODULE_TYPE_NOKEEP
MODULE_CNFNAME("omhttps")

/* internal structures
 */
DEF_OMOD_STATIC_DATA
DEFobjCurrIf(errmsg)
DEFobjCurrIf(glbl)
DEFobjCurrIf(datetime)

/* local definitions */
#define OMHTTPS_VERSION "1.0"
#define OMHTTPS_DEFAULT_PORT 5000
#define OMHTTPS_DEFAULT_USER ""
#define OMHTTPS_DEFAULT_HOST "10.150.88.130" /* ip of REST web service */

/* #define HTTPS_URL_PREFIX_V1     "" This is for hdfs so disabling */
/* #define HTTPS_URL_PREFIX_V1_SSL "" This is for hdfs so disabling */
#define HTTPS_CONTENT_TYPE      "Content-Type: application/json" /* was octet-stream */
#define HTTPS_USER_AGENT        "omhttps by rdoctor/" OMHTTPS_VERSION

#define HTTPS_CONTENT_TYPE_JSON "application/json"
#define HTTPS_JSON_BOOLEAN_TRUE "{\"boolean\":true}"

#define HTTPS_FILEALREADYEXISTSEXCEPTION "FileAlreadyExistsException"

#define HTTPS_URL_BUFFER_LENGTH 2048
#define HTTPS_JSON_BUFFER_LENGTH 2048

/*
Examples: 
module(load="omhttps")
template(name="https_tmp_file" type="string" string="/tmp/%$YEAR%/test.log")
template(name="https_tmp_filecontent" type="string" string="%$YEAR%-%$MONTH%-%$DAY% %MSG% END\n")
local4.*    action(type="omhttps" host="10.1.1.161" port="14000" https="off" file="tmp_file" isDynFile="on")
local5.*    action(type="omhttps" host="10.1.1.161" port="14000" https="off" file="tmp_file" isDynFile="on" template="https_tmp_filecontent")
*/

#define DPP(x) DBGPRINTF("OMHTTPS: %s:%d %s(): %s\n", __FILE__, __LINE__, __FUNCTION__, x)

/**
 * Exception object
 *
 */
typedef struct _HTTPS_JSON_REMOTE_EXCEPTION {
    char message[1024];
    char exception[256];
    char class[256];
} https_json_remote_exception;


typedef struct _instanceData {
    sbool https;
    uchar* host;
    uchar* ip;
    int  port;
    uchar* user;

    int timeout;
    uchar* file;
    sbool isDynFile;

    uchar* tplName;
} instanceData;


typedef struct wrkrInstanceData {
    instanceData *pData;

    CURL* curl;

    uchar* file;

    int replyLen;
    char* reply;
} wrkrInstanceData_t;


/* tables for interfacing with the v6 config system */
/* action (instance) parameters */
static struct cnfparamdescr actpdescr[] = {
    { "host", eCmdHdlrGetWord, 0 },
    { "port", eCmdHdlrInt, 0 },
    { "user", eCmdHdlrGetWord, 0 },
    { "https", eCmdHdlrBinary, 0 },
    { "file", eCmdHdlrGetWord, CNFPARAM_REQUIRED },
    { "isdynfile", eCmdHdlrBinary, 0 },
    { "template", eCmdHdlrGetWord, 0 },
};
static struct cnfparamblk actpblk = {
    CNFPARAMBLK_VERSION,
    sizeof(actpdescr)/sizeof(struct cnfparamdescr),
    actpdescr
};

/**
 * curl init
 *
 * @param wrkrInstanceData_t *pWrkrData
 * @param instanceData *pData
 * @return rsRetVal
 */
static rsRetVal
https_init_curl(wrkrInstanceData_t *pWrkrData, instanceData *pData)
{
    CURL *curl = NULL;

    curl = curl_easy_init(); 
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);	
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

        if (pData->https) {
            DBGPRINTF("%s(): Enable HTTPS\n", __FUNCTION__);
            /* for ssl */
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, FALSE); /* Change to 1L to verify the peer */
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, FALSE); /* Change to 2L to verify the host */
            /* curl_easy_setopt(curl, CURLOPT_CAPATH, char *capath); Pass a char * to a zero terminated string naming a directory holding multiple CA certificates to verify the peer with. If libcurl is built against OpenSSL, the certificate directory must be prepared using the openssl c_rehash utility. */
        }
    } else {
	    /* LOG */
        errmsg.LogError(0, RS_RET_OBJ_CREATION_FAILED, "omhttps: failed to init cURL\n");

        return RS_RET_OBJ_CREATION_FAILED;
    }
    curl_easy_setopt(curl, CURLOPT_USERAGENT, HTTPS_USER_AGENT);

    pWrkrData->curl = curl;
    return RS_RET_OK;
}

/**
 * Build HTTPS URL
 *
 * @param wrkrInstanceData_t *pWrkrData
 * @param char* op
 * @param es_str_t** url_buf
 * @return rsRetVal
 */
static rsRetVal
https_build_url(wrkrInstanceData_t *pWrkrData, const char* op, es_str_t** url_buf)
{
    *url_buf = es_newStr(HTTPS_URL_BUFFER_LENGTH);

    if (pWrkrData->pData->https) {
        es_addBuf(url_buf, "https://", sizeof("https://")-1);
    } else {
        es_addBuf(url_buf, "http://", sizeof("http://")-1);
    }

    /* host */
    es_addBuf(url_buf, (char* )pWrkrData->pData->host, strlen((char*)pWrkrData->pData->host));

    /* port */
    es_addChar(url_buf, ':');
    char portBuf[6];
    snprintf(portBuf, sizeof(portBuf), "%d", pWrkrData->pData->port);
    es_addBuf(url_buf, portBuf, strlen(portBuf));

    /* prefix */
    /* es_addBuf(url_buf, HTTPS_URL_PREFIX_V1, sizeof(HTTPS_URL_PREFIX_V1)-1); */

    /* path */
    if (pWrkrData->file[0] != '/') {
        es_addChar(url_buf, '/');
    }
    es_addBuf(url_buf, (char* )pWrkrData->file, strlen((char* )pWrkrData->file));
    
    /* queries */
    /* user */
    /* es_addBuf(url_buf, "?user.name=", sizeof("?user.name=")-1);
    es_addBuf(url_buf, (char* )pWrkrData->pData->user, strlen((char* )pWrkrData->pData->user)); */
    
    /* extra parameters */
    /* es_addBuf(url_buf, op, strlen(op)); */

    return RS_RET_OK;
}

/**
 * curl set URL
 *
 * @param wrkrInstanceData_t *pWrkrData
 * @param char* op
 * @return void
 */
static void https_set_url(wrkrInstanceData_t *pWrkrData, const char* op)
{
    es_str_t* url;
    char* url_cstr;
    https_build_url(pWrkrData, op, &url);
    url_cstr = es_str2cstr(url, NULL);
    //errmsg.LogError(0, RS_RET_ERR, "CURL request fail, error url=%s\n", url_cstr);
    curl_easy_setopt(pWrkrData->curl, CURLOPT_URL, url_cstr);
    free(url_cstr);
}
/**
 * Set http method to PUT
 *
 * @param CURL* curl
 * @return void
 */
static void https_curl_set_put(CURL* curl)
{
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 0L);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(curl, CURLOPT_POST, 0L);
    curl_easy_setopt(curl, CURLOPT_PUT, 1L);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    //curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
}
/**
 * Set http method to POST
 *
 * @param CURL* curl
 * @return void
 */
static void https_curl_set_post(CURL* curl)
{
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 0L);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(curl, CURLOPT_PUT, 0L);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 0L);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    //curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
}

/**
 * Build curl slist
 * 
 * @param struct curl_slist* headers
 * @param int hdr_count
 * @param ...
 * @return struct curl_slist* 
 */
static struct curl_slist* 
https_curl_add_header(struct curl_slist* headers, int hdr_count, ...)
{
    const char* hdr;

    va_list ar;
    va_start(ar, hdr_count);
    for (; hdr_count > 0; hdr_count--) {
        hdr = va_arg(ar, const char*);

        if (hdr != NULL
                && hdr[0] != 0) {
            /* non-empty string */
            headers = curl_slist_append(headers, hdr);
        } else {
            break;
        }
    }
    va_end(ar);

    //headers = curl_slist_append(headers, "Expect:");
    //headers = curl_slist_append(headers, "Transfer-Encoding:");

    return headers;
}

/**
 * Callback function for CURLOPT_WRITEFUNCTION
 *
 * @param void* contents
 * @param size_t size
 * @param size_t nmemb
 * @param void *userp
 * @return size_t
 */
static size_t
https_curl_result_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    char *newreply = NULL;
    wrkrInstanceData_t *mem = (wrkrInstanceData_t *)userp;
    
    newreply = realloc(mem->reply, mem->replyLen + realsize + 1);
    if (newreply == NULL) {
        /* out of memory! */
        dbgprintf("not enough memory (realloc returned NULL)\n");
        
        if (mem->reply != NULL) 
            free(mem->reply);
        
        mem->reply = NULL;
        mem->replyLen = 0;
        
        return 0;
    }

    mem->reply = newreply;
    memcpy(&(mem->reply[mem->replyLen]), contents, realsize);
    mem->replyLen += realsize;
    mem->reply[mem->replyLen] = 0;

    return realsize;
}

/**
 * Variables declaration
 * used in https related operation
 */
#define HTTPS_CURL_VARS_INIT \
    struct curl_slist* headers = NULL; \
    long response_code; \
    CURLcode res; \
    char* content_type;

/**
 * Resource release
 * used in https related operation
 */
#define HTTPS_CURL_VARS_RELEASE \
    curl_slist_free_all(headers);

/**
 * Curl execution
 * used in https related operation
 */
#define HTTPS_CURL_EXEC \
    pWrkrData->reply = NULL; \
    pWrkrData->replyLen = 0; \ 
    res = curl_easy_perform(pWrkrData->curl); \
    if (res == CURLE_OK) { \
        curl_easy_getinfo(pWrkrData->curl, CURLINFO_CONTENT_TYPE, &content_type); \
        if (strncmp(content_type, HTTPS_CONTENT_TYPE_JSON, strlen(HTTPS_CONTENT_TYPE_JSON))) { \
        } \
        curl_easy_getinfo(pWrkrData->curl, CURLINFO_RESPONSE_CODE, &response_code); \
        if (pWrkrData->reply != NULL) { \
            pWrkrData->reply[pWrkrData->replyLen] = '\0'; \
        } \
    } else { \
	errmsg.LogError(0, RS_RET_ERR, "CURL request fail, code=%d, error string=%s\n", res, curl_easy_strerror(res)); \
        return -1; \
    }

/**
 * Parse remote exception json string
 *
 * @param char* buf
 * @param int   length
 * @param https_json_remote_exception* jre
 * @return rsRetVal
 */
static rsRetVal
https_parse_exception(char* buf, int length, https_json_remote_exception* jre)
{	
	DEFiRet;
	
    if (!length) {
        return RS_RET_JSON_PARSE_ERR;
    }

    struct json_tokener* jt = json_tokener_new();
    json_tokener_reset(jt);

    struct json_object *json;
    json = json_tokener_parse_ex(jt, buf, length);
    if (!json_object_is_type(json, json_type_object)) {
		ABORT_FINALIZE(RS_RET_JSON_PARSE_ERR);
    }

    if (!json_object_object_get_ex(json, "RemoteException", &json)) {
	ABORT_FINALIZE(RS_RET_JSON_PARSE_ERR);
    }

    struct json_object *jobj;

    memset(jre, 0, sizeof(*jre));

    const char *str;
    size_t len;

    json_object_object_get_ex(json, "javaClassName", &jobj);
    str = json_object_get_string(jobj);
    len = strlen(str);
    strncpy(jre->class, str, len);

    json_object_object_get_ex(json, "exception", &jobj);
    str = json_object_get_string(jobj);
    len = strlen(str);
    strncpy(jre->exception, str, len);

    json_object_object_get_ex(json, "message", &jobj);
    str = json_object_get_string(jobj);
    len = strlen(str);
    strncpy(jre->message, str, len);

finalize_it:
	if(jt != NULL)
		json_tokener_free(jt);
	if(json != NULL)
		json_object_put(json); 
	RETiRet;
}	



/**
 * Create a file
 * op=CREATE
 * overwrite is turned off
 * 
 * @param wrkrInstanceData_t *pWrkrData
 * @param char*   buf
 * @return rsRetVal
 */
static rsRetVal
https_create_file(wrkrInstanceData_t *pWrkrData, uchar* buf)
{
    /* https.create automatically create folders, no mkdirs needed. */

    /* 
    curl -b /tmp/c.tmp -c /tmp/c.tmp  -d 'aaaaabbbbb' -i -H 'Content-Type: application/octet-stream' -X PUT \
           'http://172.16.3.20:14000/webhdfs/v1/tmp/a/b?user.name=hdfs&op=create&data=true'
    */
HTTPS_CURL_VARS_INIT
    DBGPRINTF("%s(): file=%s\n", __FUNCTION__, pWrkrData->file);
    https_curl_set_put(pWrkrData->curl);

    /*
overwrite - if a file with this name already exists, then if true, the file will be overwritten, and if false an error will be thrown.
bufferSize - the size of the buffer to be used.
replication - required block replication for the file.
     */
    https_set_url(pWrkrData, "&op=create&overwrite=false&data=true");

    /* create json object for put */
    json_object * json = json_object_new_object();

    /* build put data */
    json_object_object_add(json, "title", json_object_new_string("rsyslog"));
    json_object_object_add(json, "body", json_object_new_string((char *) buf));

    curl_easy_setopt(pWrkrData->curl, CURLOPT_POSTFIELDS, json_object_to_json_string(json));
    curl_easy_setopt(pWrkrData->curl, CURLOPT_POSTFIELDSIZE, strlen(json_object_to_json_string(json)));

    DBGPRINTF("%s(): msg=%s\n", __FUNCTION__, buf);

    headers = https_curl_add_header(headers, 1, HTTPS_CONTENT_TYPE);
    curl_easy_setopt(pWrkrData->curl, CURLOPT_HTTPHEADER, headers);
    
HTTPS_CURL_EXEC

    /* free json object */
    json_object_put(json);

    int success = 0;

    if (response_code == 200 || response_code == 201) {
        success = 1;
    }

HTTPS_CURL_VARS_RELEASE
    if (success) {
        return RS_RET_OK;
    } else {
        return RS_RET_FALSE;
    }
}

/**
 * Append to file
 * op=APPEND
 *
 * @param wrkrInstanceData_t *pWrkrData
 * @param char*   buf
 * @return rsRetVal
 */
static rsRetVal
https_append_file(wrkrInstanceData_t *pWrkrData, uchar* buf)
{
    /*
    curl -b /tmp/c.tmp -c /tmp/c.tmp  -d 'aaaaabbbbb' -i -H 'Content-Type: application/octet-stream' \
           'http://172.16.3.20:14000/webhdfs/v1/tmp/a/b?user.name=hdfs&op=append&data=true'
    */
HTTPS_CURL_VARS_INIT
    DBGPRINTF("%s(): file=%s\n", __FUNCTION__, pWrkrData->file);
    https_curl_set_post(pWrkrData->curl);
    https_set_url(pWrkrData, "&op=append&data=true");

    /* create json object for post */
    json_object * json = json_object_new_object();

    /* build put data */
    json_object_object_add(json, "title", json_object_new_string("rsyslog"));
    json_object_object_add(json, "body", json_object_new_string((char *) buf));

    curl_easy_setopt(pWrkrData->curl, CURLOPT_POSTFIELDS, json_object_to_json_string(json));
    curl_easy_setopt(pWrkrData->curl, CURLOPT_POSTFIELDSIZE, strlen(json_object_to_json_string(json)));

    headers = https_curl_add_header(headers, 1, HTTPS_CONTENT_TYPE);
    curl_easy_setopt(pWrkrData->curl, CURLOPT_HTTPHEADER, headers);
    DBGPRINTF("%s(): msg=%s\n", __FUNCTION__, buf);

HTTPS_CURL_EXEC

    /* free json object */
    json_object_put(json);

    int success = 0;

    if (response_code == 201 || response_code == 200) {
        success = 1;
    } else if (response_code == 404) {
        /* TODO: 404 ? */
        
    }
HTTPS_CURL_VARS_RELEASE
    if (success) {
        return RS_RET_OK;
    } else {
        return RS_RET_FALSE;
    }
}

/**
 * https log 
 *
 * @param wrkrInstanceData_t *pWrkrData
 * @param uchar* buf
 * @return rsRetVal
 */
static rsRetVal
https_log(wrkrInstanceData_t *pWrkrData, uchar* buf)
{
    /**
    append ? 200/end : (404 || ?)
        create & ~overwrite ? 201/200/end :
            append ? 200/end : error ?
    */
    DEFiRet;

    long response_code;
    https_json_remote_exception jre;
    iRet = https_append_file(pWrkrData, buf);
    if (iRet == RS_RET_OK) {
        DBGPRINTF("omhttps: Append success: %s\n", pWrkrData->file);
        return RS_RET_OK;
    }

    curl_easy_getinfo(pWrkrData->curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 404) {
        /* TODO: log error */
        DBGPRINTF("omhttps: Append fail HTTP %ld: %s\n", response_code, pWrkrData->file);
        return RS_RET_FALSE;
    }

    iRet = https_create_file(pWrkrData, buf);
    if (iRet == RS_RET_OK) {
        DBGPRINTF("omhttps: Create file success: %s\n", pWrkrData->file);
        return RS_RET_OK;
    }

    curl_easy_getinfo(pWrkrData->curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code == 201) {
        DBGPRINTF("omhttps: Create file success HTTP 201: %s\n", pWrkrData->file);
        return RS_RET_OK;
    }

    if (response_code == 500) {
        DBGPRINTF("omhttps: Create file failed HTTP %ld: %s\n", response_code, pWrkrData->file);
        https_parse_exception(pWrkrData->reply, pWrkrData->replyLen, &jre);
        if (!strncmp(jre.exception, HTTPS_FILEALREADYEXISTSEXCEPTION, strlen(HTTPS_FILEALREADYEXISTSEXCEPTION))) {
            /* file exists, go to append */
            DBGPRINTF("omhttps: File already exists, append again: %s\n", pWrkrData->file);

            iRet = https_append_file(pWrkrData, buf);
            if (iRet == RS_RET_OK) {
                DBGPRINTF("omhttps: Re-Append success: %s\n", pWrkrData->file);
                return RS_RET_OK;
            } else {
                DBGPRINTF("omhttps: Re-Append failed: %s\n", pWrkrData->file);
                /* error
                   exit */
            }

        } else {
            DBGPRINTF("omhttps: Create file failed: %s %s\n", pWrkrData->file, pWrkrData->reply);
        }
    } else {
        DBGPRINTF("omhttps: Create file failed: %s %s\n", pWrkrData->file, pWrkrData->reply);
    }

    return RS_RET_FALSE;
}


BEGINinitConfVars
    CODESTARTinitConfVars
ENDinitConfVars


BEGINcreateInstance
CODESTARTcreateInstance
    DBGPRINTF("omhttps: createInstance\n");
ENDcreateInstance


BEGINcreateWrkrInstance
CODESTARTcreateWrkrInstance
    DBGPRINTF("omhttps: createWrkrInstance\n");
    pWrkrData->curl = NULL;
    CHKiRet(https_init_curl(pWrkrData, pWrkrData->pData));
finalize_it:
    DBGPRINTF("omhttps: createWrkrInstance,pData %p/%p, pWrkrData %p\n", pData, pWrkrData->pData, pWrkrData);
ENDcreateWrkrInstance


BEGINisCompatibleWithFeature
CODESTARTisCompatibleWithFeature
    if(eFeat == sFEATURERepeatedMsgReduction)
        iRet = RS_RET_OK;
ENDisCompatibleWithFeature


BEGINfreeInstance
CODESTARTfreeInstance
    free(pData->file);
    free(pData->tplName);
    free(pData->host);
    free(pData->user);
ENDfreeInstance


BEGINfreeWrkrInstance
CODESTARTfreeWrkrInstance
    free(pWrkrData->file);

    if(pWrkrData->curl) {
        curl_easy_cleanup(pWrkrData->curl);
        pWrkrData->curl = NULL;
    }
ENDfreeWrkrInstance


BEGINdbgPrintInstInfo
CODESTARTdbgPrintInstInfo
    DBGPRINTF("OmHTTPS\n");
    DBGPRINTF("Version: %s\n", OMHTTPS_VERSION);
    DBGPRINTF("\tHost: %s\n", pData->host);
    DBGPRINTF("\tPort: %d\n", pData->port);
    DBGPRINTF("\tUser: %s\n", pData->user);
    DBGPRINTF("\tFile: %s\n", pData->file);
ENDdbgPrintInstInfo


BEGINtryResume
CODESTARTtryResume
    DBGPRINTF("omhttps: tryResume called\n");
    /* TODO: test networking */
    iRet = RS_RET_OK;
ENDtryResume

/**
* Do Action
*/
BEGINdoAction
CODESTARTdoAction
    DBGPRINTF("omhttps: doAction\n");
    /* dynamic file name */
    if (pWrkrData->pData->isDynFile) {
        pWrkrData->file = ustrdup(ppString[1]);
    } else {
        pWrkrData->file = ustrdup(pWrkrData->pData->file);
    }

    /* ppString[0] -> log content */
    iRet = https_log(pWrkrData, ppString[0]);

    if(iRet != RS_RET_OK) {
        DBGPRINTF("omhttps: error writing https, suspending\n");
        iRet = RS_RET_SUSPENDED;
    }
ENDdoAction



/**
 * Set default parameters
 *
 * @param instanceData *pData
 * @return void
 */
static inline void
setInstParamDefaults(instanceData *pData)
{
    pData->host = (uchar*) strdup(OMHTTPS_DEFAULT_HOST);
    pData->port = OMHTTPS_DEFAULT_PORT;
    pData->user = (uchar*) strdup(OMHTTPS_DEFAULT_USER);
    pData->https = 0;

    pData->file = NULL;
    pData->isDynFile = 0;
    pData->tplName = NULL;
}


BEGINnewActInst
    struct cnfparamvals *pvals;
    int i;
    uchar *tplToUse;
CODESTARTnewActInst
    if((pvals = nvlstGetParams(lst, &actpblk, NULL)) == NULL) {
        ABORT_FINALIZE(RS_RET_MISSING_CNFPARAMS);
    }

    CHKiRet(createInstance(&pData));
    setInstParamDefaults(pData);

    for(i = 0 ; i < actpblk.nParams ; ++i) {
        if(!pvals[i].bUsed)
            continue;
        if(!strcmp(actpblk.descr[i].name, "host")) {
            pData->host = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else if(!strcmp(actpblk.descr[i].name, "port")) {
            pData->port = (int) pvals[i].val.d.n;
        } else if(!strcmp(actpblk.descr[i].name, "user")) {
            pData->user = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);

        } else if(!strcmp(actpblk.descr[i].name, "https")) {
            pData->https = pvals[i].val.d.n ? 1 : 0;

        } else if(!strcmp(actpblk.descr[i].name, "file")) {
            pData->file = (uchar *) es_str2cstr(pvals[i].val.d.estr, NULL);

        } else if(!strcmp(actpblk.descr[i].name, "isdynfile")) {
            pData->isDynFile = pvals[i].val.d.n ? 1 : 0;

        } else if(!strcmp(actpblk.descr[i].name, "template")) {
            pData->tplName = (uchar*)es_str2cstr(pvals[i].val.d.estr, NULL);
        } else {
            DBGPRINTF("omhttps: program error, non-handled param '%s'\n", actpblk.descr[i].name);
        }
    }
    if(pData->file == NULL) {
	/* Note: this is primarily to make clang static analyzer happy, as we
	 * request via pblk that file is a mandatory parameter. However, this is
	 * also a guard against something going really wrong...
	 */
        errmsg.LogError(0, RS_RET_INTERNAL_ERROR, "omhttps: file is not set "
		"[this should not be possible]\n");
	ABORT_FINALIZE(RS_RET_INTERNAL_ERROR);
    }
    if(pData->user == NULL || pData->user[0] == '\0') {
        pData->user = ustrdup((uchar*) OMHTTPS_DEFAULT_USER);
    }
    if(pData->host == NULL || pData->host[0] == '\0') {
        pData->host = ustrdup((uchar*) OMHTTPS_DEFAULT_HOST);
    }

    if (pData->isDynFile) {
        CODE_STD_STRING_REQUESTparseSelectorAct(2)

        CHKiRet(OMSRsetEntry(*ppOMSR, 1, ustrdup(pData->file), OMSR_NO_RQD_TPL_OPTS));
    } else {
        CODE_STD_STRING_REQUESTparseSelectorAct(1)
    }

    tplToUse = ustrdup((pData->tplName == NULL) ? (uchar* ) "RSYSLOG_FileFormat" : pData->tplName);
    CHKiRet(OMSRsetEntry(*ppOMSR, 0, tplToUse, OMSR_NO_RQD_TPL_OPTS));

CODE_STD_FINALIZERnewActInst
    cnfparamvalsDestruct(pvals, &actpblk);
ENDnewActInst


BEGINparseSelectorAct
CODESTARTparseSelectorAct
    ABORT_FINALIZE(RS_RET_CONFLINE_UNPROCESSED);
CODE_STD_FINALIZERparseSelectorAct
ENDparseSelectorAct


/**
* Module Exit
*/
BEGINmodExit
CODESTARTmodExit
    /*  */
    curl_global_cleanup();

    /* release what we no longer need */
    objRelease(datetime, CORE_COMPONENT);
    objRelease(glbl, CORE_COMPONENT);
    objRelease(errmsg, CORE_COMPONENT);

ENDmodExit

/**
* Query Entry Point
*/
BEGINqueryEtryPt
CODESTARTqueryEtryPt
    CODEqueryEtryPt_STD_OMOD_QUERIES
    CODEqueryEtryPt_STD_CONF2_OMOD_QUERIES
    CODEqueryEtryPt_STD_OMOD8_QUERIES
    CODEqueryEtryPt_STD_CONF2_CNFNAME_QUERIES 
ENDqueryEtryPt


/**
* Module Init
*/
BEGINmodInit()
CODESTARTmodInit
INITLegCnfVars
    *ipIFVersProvided = CURR_MOD_IF_VERSION; /* we only support the current interface specification */
CODEmodInit_QueryRegCFSLineHdlr
    /* tell which objects we need */
    CHKiRet(objUse(errmsg, CORE_COMPONENT));
    CHKiRet(objUse(glbl, CORE_COMPONENT));
    CHKiRet(objUse(datetime, CORE_COMPONENT));

    if (curl_global_init(CURL_GLOBAL_ALL) != 0) {
        errmsg.LogError(0, RS_RET_OBJ_CREATION_FAILED, "CURL fail. -https module init failed");
        ABORT_FINALIZE(RS_RET_OBJ_CREATION_FAILED);
    }

    DBGPRINTF("omhttps version %s is initializing\n", OMHTTPS_VERSION);

ENDmodInit
