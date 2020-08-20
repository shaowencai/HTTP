#ifndef __WEBCLIENT_H__
#define __WEBCLIENT_H__


#ifdef __cplusplus
extern "C" {
#endif

#if 0
#define LOG_E(fmt,arg...)    		    setLog(4,""fmt"", ##arg);
#define LOG_D(fmt,arg...)				setLog(4,""fmt"", ##arg);	
#else
#define LOG_E(fmt,arg...)							
#define LOG_D(fmt,arg...)							
#endif

#ifndef web_malloc
#define web_malloc                     malloc
#endif

#ifndef web_calloc
#define web_calloc                     calloc
#endif

#ifndef web_realloc
#define web_realloc                    realloc
#endif

#ifndef web_free
#define web_free                       free
#endif

#ifndef web_strdup
#define web_strdup                     strdup
#endif

#define WEBCLIENT_SW_VERSION           "2.2.0"
#define WEBCLIENT_SW_VERSION_NUM       0x20200

#define WEBCLIENT_HEADER_BUFSZ         4096
#define WEBCLIENT_RESPONSE_BUFSZ       4096

enum WEBCLIENT_STATUS
{
    WEBCLIENT_OK,
    WEBCLIENT_ERROR,
    WEBCLIENT_TIMEOUT,
    WEBCLIENT_NOMEM,
    WEBCLIENT_NOSOCKET,
    WEBCLIENT_NOBUFFER,
    WEBCLIENT_CONNECT_FAILED,
    WEBCLIENT_DISCONNECT,
    WEBCLIENT_FILE_ERROR,
    WEBCLIENT_LENGTH_ERROR,
};

enum WEBCLIENT_METHOD
{
    WEBCLIENT_USER_METHOD,
    WEBCLIENT_GET,
    WEBCLIENT_POST,
};

struct  webclient_header
{
    char *buffer;
    size_t length;                      /* content header buffer size */
    size_t size;                        /* maximum support header size */
};

struct webclient_session
{
    struct webclient_header *header;    /* webclient response header information */
    int socket;
    int resp_status;

    char *host;                         /* server host */
    char *req_url;                      /* HTTP request address*/

    int chunk_sz;
    int chunk_offset;

    int content_length;
    size_t content_remainder;           /* remainder of content length */

    char is_tls;                   		/* HTTPS connect */
    unsigned short tls_port;
    unsigned int tls_socket;
};

struct webclient_session *webclient_session_create(size_t header_sz);

int webclient_get(struct webclient_session *session, const char *URI);
int webclient_get_position(struct webclient_session *session, const char *URI, int position);
int webclient_post(struct webclient_session *session, const char *URI, const void *post_data, size_t data_len);
int webclient_close(struct webclient_session *session);
int webclient_set_timeout(struct webclient_session *session, int millisecond);
int webclient_read(struct webclient_session *session, void *buffer, size_t size);
int webclient_write(struct webclient_session *session, const void *buffer, size_t size);
int webclient_header_fields_add(struct webclient_session *session, const char *fmt, ...);
int webclient_receive_response(struct webclient_session *session, void *buf,size_t bufSize,size_t *resp_len);

#ifdef  __cplusplus
    }
#endif

#endif
