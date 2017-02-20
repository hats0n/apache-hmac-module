/* Include the required headers from httpd */
#include "httpd.h"
#include "http_log.h"
#include "http_core.h"
#include "http_protocol.h"
#include "http_request.h"

#include "apr_strings.h"
#include "apr_network_io.h"
#include "apr_md5.h"
#include "apr_sha1.h"
#include "apr_hash.h"
#include "apr_base64.h"
#include "apr_dbd.h"
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_tables.h>
#include "util_script.h"
#include "sha1.h"
#include "hmac.h"

static int hmac_access_checker(request_rec*);

/********************************************** CONFIGURATION STRUCTURE *******************************************/
typedef struct {
    char    context[256];
    int         enabled;      /* Enable or disable our module */
    int  maxAllowedDelay;
    char preSharedKey[100];         /* Pre-shared key for HMAC hashing*/
} hmac_config;

/********************************************** DIRECTIVES DEFINITION *********************************************/
/* Handler for the "examplePath" directive */
const char *hmac_set_enabled(cmd_parms *cmd, void *cfg, const char *arg)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    hmac_config    *config = (hmac_config *) cfg;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(!strcasecmp(arg, "on")) config->enabled = 1;
    else config->enabled = 0;
    return NULL;
}

const char *hmac_set_max_allowed_delay(cmd_parms *cmd, void *cfg, const char *arg)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    hmac_config    *config = (hmac_config *) cfg;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(arg){
        config->maxAllowedDelay = atoi(arg);
    }
    return NULL;
}

const char *hmac_set_pre_shared_key(cmd_parms *cmd, void *cfg, const char *arg)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    hmac_config    *config = (hmac_config *) cfg;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(arg)
    {
        strcpy(config->preSharedKey, arg);
    }
    return NULL;
}

static const command_rec hmac_directives[] =
{
        AP_INIT_TAKE1("HatsonHMACEnabled", hmac_set_enabled, NULL, ACCESS_CONF, "Enable or disable mod_hmac"),
        AP_INIT_TAKE1("HatsonHMACPreSharedKey", hmac_set_pre_shared_key, NULL, ACCESS_CONF, "PreSharedKey used in HMAC Algorithm"),
        AP_INIT_TAKE1("HatsonHMACAllowedRequestDelay", hmac_set_max_allowed_delay, NULL, ACCESS_CONF, "Allowed delay in seconds to drop requests older than that time"),
        { NULL }
};

/********************************* CREATE AND MERGE DIR FUNCTIONS **************************************************/

void *create_dir_conf(apr_pool_t *pool, char *context)
{
    context = context ? context : "Newly created configuration";

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    hmac_config    *cfg = apr_pcalloc(pool, sizeof(hmac_config));
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    if(cfg)
    {
        {
            /* Set some default values */
            strcpy(cfg->context, context);
            cfg->enabled = 0;
            cfg->maxAllowedDelay = 30;
        }
    }

    return cfg;
}

void *merge_dir_conf(apr_pool_t *pool, void *BASE, void *ADD)
{
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    hmac_config    *base = (hmac_config *) BASE;
    hmac_config    *add = (hmac_config *) ADD;
    hmac_config    *conf = (hmac_config *) create_dir_conf(pool, "Merged configuration");
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    conf->enabled = (add->enabled == 0) ? base->enabled : add->enabled;
    strcpy(conf->preSharedKey, strlen(add->preSharedKey) ? add->preSharedKey : base->preSharedKey);
    return conf;
}


/********************************************* MAIN DECLARATION **************************************************/
static void register_hooks(apr_pool_t *pool)
{
    ap_hook_access_checker(hmac_access_checker, NULL, NULL, APR_HOOK_FIRST);
}


module AP_MODULE_DECLARE_DATA   hmac_module =
        {
                STANDARD20_MODULE_STUFF,
                create_dir_conf,            // Per-directory configuration handler
                merge_dir_conf,            // Merge handler for per-directory configurations
                NULL,            // Per-server configuration handler
                NULL,            // Merge handler for per-server configurations
                hmac_directives,            // Any directives we may have for httpd
                register_hooks   // Our hook registering function
        };



/********************************************** UTILITY FUNCITON **************************************************/

static long get_timestamp() {
//    apr_time_t apr_time = apr_time_now();
//    apr_time /= 1000000;
//    apr_time /= 30;
    return (long)(time)/1000;
}

/***************************************** MAIN ACCESS CHECKER FUNCTION ********************************************/
static int hmac_access_checker(request_rec *r)
{
    long now;
    int n;
    apr_table_t* GET;
    apr_array_header_t* POST;
    long timestampL;
    const char* timestamp;
    const char* claimedHash;
    int preSharedKeyLength;
    int timestampLength;
    uint8_t* preSharedKeyBytes;
    uint8_t* timestampBytes;
    uint8_t hash[SHA1_DIGEST_LENGTH];

    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    hmac_config    *config = (hmac_config *) ap_get_module_config(r->per_dir_config, &hmac_module);
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    if(config->enabled == 0) return DECLINED;

    preSharedKeyLength = (int) strlen(config->preSharedKey);

    ap_args_to_table(r, &GET);
    ap_parse_form_data(r, NULL, &POST, -1, 8192);

    timestamp = apr_table_get(r->headers_in, "X-EPOCH");
    claimedHash = apr_table_get(r->headers_in, "X-HMAC");
    if (!timestamp){
        ap_log_rerror(APLOG_MARK,APLOG_ERR,HTTP_FORBIDDEN,r,"Timestamp does not exits in request");
        return HTTP_FORBIDDEN;
    }
    if(!claimedHash){
        ap_log_rerror(APLOG_MARK,APLOG_ERR,HTTP_FORBIDDEN,r,"There is no claimed hash in the request!");
        return HTTP_FORBIDDEN;
    }
    now = get_timestamp();
    timestampL = atol(timestamp);
    if(timestampL>now || (now-timestampL)>config->maxAllowedDelay){
        ap_log_rerror(APLOG_MARK,APLOG_ERR,HTTP_FORBIDDEN,r,"Timestamp differences is not right! : NOW:%ld, REQ-TIME:%ld",now,timestampL);
        return HTTP_FORBIDDEN;
    }
    timestampLength = (int) strlen(timestamp);

    preSharedKeyBytes = apr_palloc(r->pool, sizeof(uint8_t) * preSharedKeyLength);
    n=0;
    while(n<preSharedKeyLength){
        preSharedKeyBytes[n] = (uint8_t)config->preSharedKey[n];
        n++;
    }
    timestampBytes = apr_palloc(r->pool, sizeof(uint8_t) * strlen(timestamp));
    n=0;
    while(n<preSharedKeyLength){
        timestampBytes[n] = (uint8_t)timestamp[n];
        n++;
    }

    hmac_sha1(preSharedKeyBytes, preSharedKeyLength, timestampBytes, timestampLength, hash, SHA1_DIGEST_LENGTH);
    char *encoded = apr_palloc(r->pool,(SHA1_DIGEST_LENGTH*2)+3);
    apr_base64_encode_binary(encoded,hash,SHA1_DIGEST_LENGTH);

    if(strcmp(claimedHash,encoded)){
        ap_log_rerror(APLOG_MARK,APLOG_ERR,HTTP_FORBIDDEN,r,"Claimed hash and digested values does not match,Claimed:%s , Target:%s, PSK:%s",claimedHash,encoded,config->preSharedKey);
        return HTTP_FORBIDDEN;
    }

    //it's ok , process it further
    return OK;
}
