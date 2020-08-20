#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <va_list.h>
#include <sys/time.h>
#include <stdarg.h>

#include "webclient.h"

/* default receive or send timeout */
#define WEBCLIENT_DEFAULT_TIMEO        60

extern long int strtol(const char *nptr, char **endptr, int base);//字符串转数字接口

/*********************************************************************************
** 函数名： webclient_strncasecmp
** 功能描述：字符串比较 不区分大小写
** 作者：邵温财
** 日期：2020.02.20
** 返回：=0 字符串相等
*********************************************************************************/
static int webclient_strncasecmp(const char *a, const char *b, size_t n)
{
    uint8_t c1, c2;
    if (n <= 0)
        return 0;
    do {
        c1 = tolower(*a++);
        c2 = tolower(*b++);
    } while (--n && c1 && c1 == c2);
    return c1 - c2;
}

/*********************************************************************************
** 函数名： webclient_strstri
** 功能描述：从原字符串查找子字符串
** 作者：邵温财
** 日期：2020.02.20
** 返回：查找成功 返回子字符串起始地址
*********************************************************************************/
static const char *webclient_strstri(const char* str, const char* subStr)
{
    int len = strlen(subStr);

    if(len == 0)
    {
        return NULL;
    }

    while(*str)
    {
        if(webclient_strncasecmp(str, subStr, len) == 0)
        {
            return str;
        }
        ++str;
    }
    return NULL;
}

/*********************************************************************************
** 函数名： webclient_send
** 功能描述：tcp报文发送
** 作者：邵温财
** 日期：2020.02.20
*********************************************************************************/
static int webclient_send(struct webclient_session* session, const void *buffer, size_t len, int flag)
{
	//shao++ TLS
    if (session->is_tls == TRUE)
    {
        return HAL_SSL_Write(session->tls_socket, buffer, len);
    }
    return send(session->socket, buffer, len, flag);
}

/*********************************************************************************
** 函数名： webclient_recv
** 功能描述：tcp报文接收
** 作者：邵温财
** 日期：2020.02.20
*********************************************************************************/
static int webclient_recv(struct webclient_session* session, void *buffer, size_t len, int flag)
{
	//shao++ TLS
    if (session->is_tls == TRUE )
    {
        return HAL_SSL_Read(session->tls_socket, buffer, len,60000,1000);
    }
    return recv(session->socket, buffer, len, flag);
}


/*********************************************************************************
** 函数名： webclient_read_line
** 功能描述：读取一行到buf中
** 作者：邵温财
** 日期：2020.02.20
** 返回：成功读取的字节数  失败<0
*********************************************************************************/
static int webclient_read_line(struct webclient_session *session, char *buffer, int size)
{
    int rc, count = 0;
    char ch = 0, last_ch = 0;

    while (count < size)
    {
        rc = webclient_recv(session, (unsigned char *) &ch, 1, 0);

        if (rc <= 0) return rc;

        if (ch == '\n' && last_ch == '\r') break;	//一行的最后一个字符是'\n'

        buffer[count++] = ch;

        last_ch = ch;
    }

    if (count > size)
    {
        LOG_E("read line failed. The line data length is out of buffer size(%d)!", count);
        return -WEBCLIENT_ERROR;
    }

    return count;
}

/**************************************************************************
** 函数名： webclient_resolve_address
** 功能描述：分解服务器http请求 得到 IP 端口  请求的资源
** 作者：邵温财
** 日期：2020.02.20
** 返回：成功返回0
** 说明:
** http://www.rt-thread.org
** http://www.rt-thread.org:80
** https://www.rt-thread.org/
** http://192.168.1.1:80/index.htm
** http://[fe80::1]
** http://[fe80::1]/
** http://[fe80::1]/index.html
** http://[fe80::1]:80/index.html
***************************************************************************/
static int webclient_resolve_address(struct webclient_session *session, struct addrinfo **res,
                                     const char *url, const char **request)
{
    int rc = WEBCLIENT_OK;
    char *ptr;
    char port_str[6] = "80";
    const char *port_ptr;
    const char *path_ptr;

    const char *host_addr = 0;
    int url_len, host_addr_len = 0;

    url_len = strlen(url);

    if (strncmp(url, "http://", 7) == 0)
    {
        host_addr = url + 7;
    }
    else if (strncmp(url, "https://", 8) == 0)
    {
        strncpy(port_str, "443", 4);
        host_addr = url + 8;
    }
    else
    {
        rc = -WEBCLIENT_ERROR;
        goto __exit;
    }

    /* ipv6 address */
    if (host_addr[0] == '[')
    {
        host_addr += 1;
        ptr = strstr(host_addr, "]");
        if (!ptr)
        {
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }
        host_addr_len = ptr - host_addr;
    }

    path_ptr = strstr(host_addr, "/");
    *request = path_ptr ? path_ptr : "/";

    /* resolve port */
    port_ptr = strstr(host_addr + host_addr_len, ":");
    
    if (port_ptr && path_ptr && (port_ptr < path_ptr))
    {
        int port_len = path_ptr - port_ptr - 1;
        strncpy(port_str, port_ptr + 1, port_len);
        port_str[port_len] = '\0';
    }

    if (port_ptr && (!path_ptr))
    {
        strcpy(port_str, port_ptr + 1);
    }

    /* ipv4 or domain. */
    if (!host_addr_len)
    {
        if (port_ptr)
        {
            host_addr_len = port_ptr - host_addr;
        }
        else if (path_ptr)
        {
            host_addr_len = path_ptr - host_addr;
        }
        else
        {
            host_addr_len = strlen(host_addr);
        }
    }

    if ((host_addr_len < 1) || (host_addr_len > url_len))
    {
        rc = -WEBCLIENT_ERROR;
        goto __exit;
    }

    /* get host address ok. */
    {
        char *host_addr_new = web_malloc(host_addr_len + 1);

        if (!host_addr_new)
        {
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }

        memcpy(host_addr_new, host_addr, host_addr_len);
        host_addr_new[host_addr_len] = '\0';
        session->host = host_addr_new;
    }

    LOG_E("host address: %s,port: %s",session->host,port_str);

    if (session->is_tls)
    {
        session->tls_port = atoi(port_str);
        return rc;
    }
    
    /* resolve the host name. */
    {
        struct addrinfo hint;
        int ret;

        memset(&hint, 0, sizeof(hint));
        ret = getaddrinfo(session->host, port_str, &hint, res);
        if (ret != 0)
        {
            LOG_E("getaddrinfo err: %d '%s'.", ret, session->host);
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }
    }

__exit:
    if (rc != WEBCLIENT_OK)
    {
        if (session->host)
        {
            web_free(session->host);
            session->host = NULL;
        }

        if (*res)
        {
            freeaddrinfo(*res);
            *res = NULL;
        }
    }

    return rc;
}

static const char mbedtls_root_certificate[] = 
"-----BEGIN CERTIFICATE-----\r\n" \
"MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\r\n" \
"MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\r\n" \
"DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\r\n" \
"PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\r\n" \
"Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\r\n" \
"AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\r\n" \
"rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\r\n" \
"OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\r\n" \
"xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\r\n" \
"7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\r\n" \
"aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\r\n" \
"HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\r\n" \
"SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\r\n" \
"ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\r\n" \
"AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\r\n" \
"R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\r\n" \
"JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\r\n" \
"Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\r\n" \
"-----END CERTIFICATE-----\r\n" \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh\r\n" \
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n" \
"d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\r\n" \
"QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT\r\n" \
"MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\r\n" \
"b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG\r\n" \
"9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB\r\n" \
"CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97\r\n" \
"nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt\r\n" \
"43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P\r\n" \
"T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4\r\n" \
"gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO\r\n" \
"BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR\r\n" \
"TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw\r\n" \
"DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr\r\n" \
"hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg\r\n" \
"06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF\r\n" \
"PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls\r\n" \
"YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk\r\n" \
"CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=\r\n" \
"-----END CERTIFICATE-----\r\n" \
"-----BEGIN CERTIFICATE-----\r\n" \
"MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\r\n" \
"MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\r\n" \
"DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\r\n" \
"PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\r\n" \
"Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\r\n" \
"AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\r\n" \
"rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\r\n" \
"OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\r\n" \
"xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\r\n" \
"7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\r\n" \
"aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\r\n" \
"HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\r\n" \
"SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\r\n" \
"ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\r\n" \
"AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\r\n" \
"R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\r\n" \
"JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\r\n" \
"Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\r\n" \
"-----END CERTIFICATE-----\r\n" \

;

static const size_t mbedtls_root_certificate_len = sizeof(mbedtls_root_certificate);
/**************************************************************************
** 函数名： webclient_connect
** 功能描述：连接HTTP服务器
** 作者：邵温财
** 日期：2020.02.20
** 返回：成功返回0
***************************************************************************/
static int webclient_connect(struct webclient_session *session, const char *URI)
{
    int rc = WEBCLIENT_OK;
    int socket_handle;
    struct timeval timeout;
    struct addrinfo *res = NULL;
    const char *req_url = NULL;

    timeout.tv_sec = WEBCLIENT_DEFAULT_TIMEO;
    timeout.tv_usec = 0;

    if (strncmp(URI, "https://", 8) == 0)
    {
        session->is_tls = TRUE;
    }

    /* Check valid IP address and URL */
    rc = webclient_resolve_address(session, &res, URI, &req_url);
    if (rc != WEBCLIENT_OK)
    {
        LOG_E("connect failed, resolve address error(%d).", rc);
        goto __exit;
    }

    /* Not use 'getaddrinfo()' for https connection */
    if (session->is_tls == FALSE && res == NULL)
    {
        rc = -WEBCLIENT_ERROR;
        goto __exit;
    }

    /* copy host address */
    if (req_url)
    {
        session->req_url = web_strdup(req_url);
    }
    else
    {
        LOG_E("connect failed, resolve request address error.");
        rc = -WEBCLIENT_ERROR;
        goto __exit;
    }

	//shao++ tls
    if (session->is_tls == TRUE)
    {	
		session->tls_socket = HAL_SSL_Establish(session->host,session->tls_port, mbedtls_root_certificate, mbedtls_root_certificate_len);
		if(session->tls_socket == 0)
		{
            LOG_E("connect failed, connect socket error.");
            rc = -WEBCLIENT_CONNECT_FAILED;
		}
		return rc;
    }
    else 
    {
        socket_handle = socket(res->ai_family, SOCK_STREAM, 6);

        if (socket_handle < 0)
        {
            LOG_E("connect failed, create socket(%d) error.", socket_handle);
            rc = -WEBCLIENT_NOSOCKET;
            goto __exit;
        }

        /* set receive and send timeout option */
        setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO, (void *) &timeout,
                   sizeof(timeout));
        setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO, (void *) &timeout,
                   sizeof(timeout));

        if (connect(socket_handle, res->ai_addr, res->ai_addrlen) != 0)
        {
            /* connect failed, close socket */
            LOG_E("connect failed, connect socket(%d) error.", socket_handle);
            cmClose(socket_handle);
            rc = -WEBCLIENT_CONNECT_FAILED;
            goto __exit;
        }

        session->socket = socket_handle;
    }

__exit:
    if (res)
    {
        freeaddrinfo(res);
    }

    return rc;
}


/**************************************************************************
** 函数名： webclient_header_fields_add
** 功能描述：添加字段到请求头部
** 作者：邵温财
** 日期：2020.02.20
** 返回：成功返回添加的字节数
***************************************************************************/
int webclient_header_fields_add(struct webclient_session *session, const char *fmt, ...)
{
    int32_t length;
    va_list *args;

    va_start(args, fmt);
    length = vsnprintf(session->header->buffer + session->header->length,
            session->header->size - session->header->length, fmt, args);
    if (length < 0)
    {
        LOG_E("add fields header data failed, return length(%d) error.", length);
        return -WEBCLIENT_ERROR;
    }
    va_end(args);

    session->header->length += length;

    /* check header size */
    if (session->header->length >= session->header->size)
    {
        LOG_E("not enough header buffer size(%d)!", session->header->size);
        return -WEBCLIENT_ERROR;
    }

    return length;
}

/**************************************************************************
** 函数名： webclient_header_fields_get
** 功能描述：从头部获取指定字段的value
** 作者：邵温财
** 日期：2020.02.20
** 返回：成功返回指定字段的value
***************************************************************************/
static const char *webclient_header_fields_get(struct webclient_session *session, const char *fields)
{
    char *resp_buf = NULL;
    size_t resp_buf_len = 0;

    resp_buf = session->header->buffer;
    while (resp_buf_len < session->header->length)
    {
        if (webclient_strstri(resp_buf, fields))
        {
            char *mime_ptr = NULL;

            /* jump space */
            mime_ptr = strstr(resp_buf, ":");
            if (mime_ptr != NULL)
            {
                mime_ptr += 1;

                while (*mime_ptr && (*mime_ptr == ' ' || *mime_ptr == '\t')) mime_ptr++;

                return mime_ptr;
            }
        }

        if (*resp_buf == '\0') break;

        resp_buf += strlen(resp_buf) + 1;
        resp_buf_len += strlen(resp_buf) + 1;
    }

    return NULL;
}

/**************************************************************************
** 函数名： webclient_resp_status_get
** 功能描述：获取服务器返回的应答状态
** 作者：邵温财
** 日期：2020.02.20
***************************************************************************/
static int webclient_resp_status_get(struct webclient_session *session)
{
    return session->resp_status;
}

/**************************************************************************
** 函数名： webclient_content_length_get
** 功能描述：获取服务器返回的数据长度
** 作者：邵温财
** 日期：2020.02.20
** 返回：数据长度
***************************************************************************/
int webclient_content_length_get(struct webclient_session *session)
{
    return session->content_length;
}

/**************************************************************************
** 函数名：webclient_send_header
** 功能描述：发送HTTP头部信息
** 作者：邵温财
** 日期：2020.02.20
***************************************************************************/
static int webclient_send_header(struct webclient_session *session, int method)
{
    int rc = WEBCLIENT_OK;
    char *header = NULL;

    header = session->header->buffer;

    /* 如果头部的长度为0 说明用户还没有填充头部信息  就填充默认的头部信息 */ 
    if (session->header->length == 0)
    {
        /* use default header data */
        if (webclient_header_fields_add(session, "GET %s HTTP/1.1\r\n", session->req_url) < 0)
            return -WEBCLIENT_NOMEM;
        if (webclient_header_fields_add(session, "Host: %s\r\n", session->host) < 0)
            return -WEBCLIENT_NOMEM;
        if (webclient_header_fields_add(session, "User-Agent: CET HTTP Agent\r\n\r\n") < 0)
            return -WEBCLIENT_NOMEM;

        webclient_write(session, (unsigned char *) session->header->buffer, session->header->length);
    }
    else
    {
        if (method != WEBCLIENT_USER_METHOD)
        {
            /* 如果头部没有添加HTTP版本 就加上HTTP请求信息 */
            if (memcmp(header, "HTTP/1.", strlen("HTTP/1.")))
            {
                char *header_buffer = NULL;
                int length = 0;

                header_buffer = web_strdup(session->header->buffer);
                if (header_buffer == NULL)
                {
                    LOG_E("no memory for header buffer!");
                    rc = -WEBCLIENT_NOMEM;
                    goto __exit;
                }

                /* splice http request header data */
                if (method == WEBCLIENT_GET)
                    length = snprintf(session->header->buffer, session->header->size, "GET %s HTTP/1.1\r\n%s",
                            session->req_url ? session->req_url : "/", header_buffer);
                else if (method == WEBCLIENT_POST)
                    length = snprintf(session->header->buffer, session->header->size, "POST %s HTTP/1.1\r\n%s",
                            session->req_url ? session->req_url : "/", header_buffer);
                session->header->length = length;

                web_free(header_buffer);
            }

            if (strstr(header, "Host:") == NULL)
            {
                if (webclient_header_fields_add(session, "Host: %s\r\n", session->host) < 0)
                    return -WEBCLIENT_NOMEM;
            }

            if (strstr(header, "User-Agent:") == NULL)
            {
                if (webclient_header_fields_add(session, "User-Agent: CET HTTP Agent\r\n") < 0)
                    return -WEBCLIENT_NOMEM;
            }

            if (strstr(header, "Accept:") == NULL)
            {
                if (webclient_header_fields_add(session, "Accept: */*\r\n") < 0)
                    return -WEBCLIENT_NOMEM;
            }

            /* header data end */
            snprintf(session->header->buffer + session->header->length, session->header->size, "\r\n");
            session->header->length += 2;

            /* check header size */
            if (session->header->length > session->header->size)
            {
                LOG_E("send header failed, not enough header buffer size(%d)!", session->header->size);
                rc = -WEBCLIENT_NOBUFFER;
                goto __exit;
            }

            webclient_write(session, (unsigned char *) session->header->buffer, session->header->length);
        }
        else
        {
            webclient_write(session, (unsigned char *) session->header->buffer, session->header->length);
        }
    }

    /* 输出请求的头部信息到日志文件 */
    {
        char *header_str, *header_ptr;
        int header_line_len;
        LOG_E("request header:");

        for(header_str = session->header->buffer; (header_ptr = strstr(header_str, "\r\n")) != NULL; )
        {
            header_line_len = header_ptr - header_str;

            if (header_line_len > 0)
            {
                LOG_E("%d.%s", header_line_len, header_str);
            }
            header_str = header_ptr + strlen("\r\n");
        }
    }

__exit:
    return rc;
}


/**************************************************************************
** 函数名：webclient_handle_response
** 功能描述：处理服务器返回的头部信息
** 作者：邵温财
** 日期：2020.02.20
** 返回：<0 处理失败      =0 成功
***************************************************************************/
int webclient_handle_response(struct webclient_session *session)
{
    int rc = WEBCLIENT_OK;
    char *mime_buffer = NULL;
    char *mime_ptr = NULL;
    const char *transfer_encoding;
    int i;

    memset(session->header->buffer, 0x00, session->header->size);
    session->header->length = 0;

    LOG_E("response header:");
    
    /* 读取返回的头部信息到缓冲中 */
    while (1)
    {
        mime_buffer = session->header->buffer + session->header->length;
        rc = webclient_read_line(session, mime_buffer, session->header->size - session->header->length);
        if (rc < 0)break;

        if (rc == 0) break;
        
        if ((rc == 1) && (mime_buffer[0] == '\r'))
        {
            mime_buffer[0] = '\0';
            break;
        }

        mime_buffer[rc - 1] = '\0';

        LOG_E("%s", mime_buffer);

        session->header->length += rc;

        if (session->header->length >= session->header->size)
        {
            LOG_E("not enough header buffer size(%d)!", session->header->size);
            return -WEBCLIENT_NOMEM;
        }
    }

    /* get HTTP status code */
    mime_ptr = web_strdup(session->header->buffer);
    if (mime_ptr == NULL)
    {
        LOG_E("no memory for get http status code buffer!");
        return -WEBCLIENT_NOMEM;
    }

    if (strstr(mime_ptr, "HTTP/1."))
    {
        char *ptr = mime_ptr;

        ptr += strlen("HTTP/1.x");

        while (*ptr && (*ptr == ' ' || *ptr == '\t')) ptr++;
        
        for (i = 0; ((ptr[i] != ' ') && (ptr[i] != '\t')); i++);
        
        ptr[i] = '\0';

        session->resp_status = (int) strtol(ptr, NULL, 10);
    }

    /* get content length */
    if (webclient_header_fields_get(session, "Content-Length") != NULL)
    {
        session->content_length = atoi(webclient_header_fields_get(session, "Content-Length"));
    }
    session->content_remainder = session->content_length ? (size_t) session->content_length : 0xFFFFFFFF;

    transfer_encoding = webclient_header_fields_get(session, "Transfer-Encoding");
    if (transfer_encoding && strcmp(transfer_encoding, "chunked") == 0)
    {
        char line[16];

        /* chunk mode, we should get the first chunk size */
        webclient_read_line(session, line, session->header->size);
        session->chunk_sz = strtol(line, NULL, 16);
        session->chunk_offset = 0;
    }

    if (mime_ptr)
    {
        web_free(mime_ptr);
    }

    if (rc < 0)
    {
        return rc;
    }

    return session->resp_status;
}


/**************************************************************************
** 函数名：webclient_clean
** 功能描述：关闭sock 释放host和request url
** 作者：邵温财
** 日期：2020.02.20
***************************************************************************/
static int webclient_clean(struct webclient_session *session)
{
	if (session->is_tls == TRUE)
	{
		session->is_tls = FALSE;
		if(session->tls_socket != 0)
		{
			HAL_SSL_Destroy(session->tls_socket);
			session->tls_socket = 0;
		}
	}
	
    if (session->socket >= 0)
    {
        cmClose(session->socket);
        session->socket = -1;
    }
    if (session->host)
    {
        web_free(session->host);
        session->host = NULL;
    }
    if (session->req_url)
    {
        web_free(session->req_url);
        session->req_url = NULL;
    }
    session->content_length = -1;

    return 0;
}

/**************************************************************************
** 函数名：webclient_next_chunk
** 功能描述：得到下一块数据的大小
** 作者：邵温财
** 日期：2020.02.20
***************************************************************************/
static int webclient_next_chunk(struct webclient_session *session)
{
    char line[64];
    int length;

    memset(line, 0x00, sizeof(line));
    length = webclient_read_line(session, line, sizeof(line));
    if (length > 0)
    {
        if (strcmp(line, "\r") == 0)
        {
            length = webclient_read_line(session, line, sizeof(line));
            if (length <= 0)
            {
            	if(session->tls_socket)
            	{
            		HAL_SSL_Destroy(session->tls_socket);
            		session->tls_socket = 0;
            	}
            	else
            	{
            		cmClose(session->socket);
            		session->socket = -1;
            	}
                
                return length;
            }
        }
    }
    else
    {	
    	if(session->tls_socket)
    	{
    		HAL_SSL_Destroy(session->tls_socket);
    		session->tls_socket = 0;
    	}
    	else
    	{
    		cmClose(session->socket);
    		session->socket = -1;
    	}

        return length;
    }

    session->chunk_sz = strtol(line, NULL, 16);
    session->chunk_offset = 0;

    if (session->chunk_sz == 0)
    {
        /* end of chunks */
    	if(session->tls_socket)
    	{
    		HAL_SSL_Destroy(session->tls_socket);
    		session->tls_socket = 0;
    	}
    	else
    	{
    		cmClose(session->socket);
    		session->socket = -1;
    	}
        session->chunk_sz = -1;
    }

    return session->chunk_sz;
}



/**************************************************************************
** 函数名：webclient_session_create
** 功能描述：创建会话结构体
** 参数：header_sz 指定会话的头部大小
** 作者：邵温财
** 日期：2020.02.20
** 返回：成功返回结构体地址 失败返回NULL
***************************************************************************/
struct webclient_session *webclient_session_create(size_t header_sz)
{
    struct webclient_session *session;

    /* create session */
    session = (struct webclient_session *) web_calloc(1, sizeof(struct webclient_session));
    if (session == NULL)
    {
        LOG_E("webclient create failed, no memory for webclient session!");
        return NULL;
    }

    /* initialize the socket of session */
    session->socket = -1;
    session->content_length = -1;

    session->header = (struct webclient_header *) web_calloc(1, sizeof(struct webclient_header));
    if (session->header == NULL)
    {
        LOG_E("webclient create failed, no memory for session header!");
        web_free(session);
        session = NULL;
        return NULL;
    }

    session->header->size = header_sz;
    session->header->buffer = (char *) web_calloc(1, header_sz);
    if (session->header->buffer == NULL)
    {
        LOG_E("webclient create failed, no memory for session header buffer!");
        web_free(session->header);
        web_free(session);
        session = NULL;
        return NULL;
    }

    return session;
}

/**************************************************************************
** 函数名：webclient_get
** 功能描述：向服务器发送请求资源
** 作者：邵温财
** 日期：2020.02.20
** 返回：成功返回状态码
***************************************************************************/
int webclient_get(struct webclient_session *session, const char *URI)
{
    int rc = WEBCLIENT_OK;
    int resp_status = 0;

    rc = webclient_connect(session, URI);
    if (rc != WEBCLIENT_OK)
    {
        return rc;
    }

    rc = webclient_send_header(session, WEBCLIENT_GET);
    if (rc != WEBCLIENT_OK)
    {
       return rc;
    }

    resp_status = webclient_handle_response(session);

    LOG_E("get handle response(%d).", resp_status);

    if (resp_status > 0)
    {
        const char *location = webclient_header_fields_get(session, "Location");

        /* 重定向  */
        if ((resp_status == 302 || resp_status == 301) && location)
        {
            char *new_url;

            new_url = web_strdup(location);
            if (new_url == NULL)
            {
                return -WEBCLIENT_NOMEM;
            }

            webclient_clean(session);
            session->header->length = 0;
            memset(session->header->buffer, 0, session->header->size);

            rc = webclient_get(session, new_url);

            web_free(new_url);
            return rc;
        }
    }

    return resp_status;
}


/**************************************************************************
** 函数名：webclient_get_position
** 功能描述：请求断点数据
** 参数：position 断点位置
** 作者：邵温财
** 日期：2020.02.20
** 返回：成功返回状态码
***************************************************************************/
int webclient_get_position(struct webclient_session *session, const char *URI, int position)
{
    int rc = WEBCLIENT_OK;
    int resp_status = 0;

    rc = webclient_connect(session, URI);
    if (rc != WEBCLIENT_OK)
    {
        return rc;
    }

    /* splice header*/
    if (webclient_header_fields_add(session, "Range: bytes=%d-\r\n", position) <= 0)
    {
        rc = -WEBCLIENT_ERROR;
        return rc;
    }

    rc = webclient_send_header(session, WEBCLIENT_GET);
    if (rc != WEBCLIENT_OK)
    {
        return rc;
    }

    /* handle the response header of webclient server */
    resp_status = webclient_handle_response(session);

    LOG_E("get position handle response(%d).", resp_status);

    if (resp_status > 0)
    {
        const char *location = webclient_header_fields_get(session, "Location");

        /* relocation */
        if ((resp_status == 302 || resp_status == 301) && location)
        {
            char *new_url;

            new_url = web_strdup(location);
            if (new_url == NULL)
            {
                return -WEBCLIENT_NOMEM;
            }

            webclient_clean(session);
            session->header->length = 0;
            memset(session->header->buffer, 0, session->header->size);

            rc = webclient_get_position(session, new_url, position);

            web_free(new_url);
            return rc;
        }
    }

    return resp_status;
}


/**************************************************************************
** 函数名：webclient_post
** 功能描述：post数据给服务器
** 作者：邵温财
** 日期：2020.02.20
** 返回：=0 成功
***************************************************************************/
int webclient_post(struct webclient_session *session, const char *URI, const void *post_data, size_t data_len)
{
    int rc = WEBCLIENT_OK;
    int resp_status = 0;

    if ((post_data != NULL) && (data_len == 0))
    {
        LOG_E("input post data length failed");
        return -WEBCLIENT_ERROR;
    }

    rc = webclient_connect(session, URI);
    if (rc != WEBCLIENT_OK)
    {
        return rc;
    }

    rc = webclient_send_header(session, WEBCLIENT_POST);
    if (rc != WEBCLIENT_OK)
    {
        return rc;
    }

    if (post_data && (data_len > 0))
    {
        webclient_write(session, post_data, data_len);
        resp_status = webclient_handle_response(session);
        LOG_E("post handle response(%d).", resp_status);
    }

    return resp_status;
}



/**************************************************************************
** 函数名：webclient_set_timeout
** 功能描述：设置发送和接收的超时时间
** 作者：邵温财
** 日期：2020.02.20
** 返回：=0 成功
***************************************************************************/
int webclient_set_timeout(struct webclient_session *session, int millisecond)
{
    struct timeval timeout;
    int second = (millisecond) / 1000;

    if(session->is_tls == TRUE)
    {
    	return 0;
    }
    
    timeout.tv_sec = second;
    timeout.tv_usec = 0;

    setsockopt(session->socket, SOL_SOCKET, SO_RCVTIMEO,
               (void *) &timeout, sizeof(timeout));
    setsockopt(session->socket, SOL_SOCKET, SO_SNDTIMEO,
               (void *) &timeout, sizeof(timeout));

    return 0;
}


/**************************************************************************
** 函数名：webclient_read
** 功能描述：接收服务器发来的数据
** 作者：邵温财
** 日期：2020.02.20
** 返回：>0 读取的字节数        =0 连接断开         <0接收错误
***************************************************************************/
int webclient_read(struct webclient_session *session, void *buffer, size_t length)
{
    int bytes_read = 0;
    int total_read = 0;
    int left;

    if (session->chunk_sz < 0)
    {
        return 0;
    }

    if (session->socket < 0 && session->tls_socket == 0)
    {
        return -WEBCLIENT_DISCONNECT;
    }

    if (length == 0)
    {
        return 0;
    }

    /* which is transfered as chunk mode */
    if (session->chunk_sz)
    {
        if ((int) length > (session->chunk_sz - session->chunk_offset))
        {
            length = session->chunk_sz - session->chunk_offset;
        }

        bytes_read = webclient_recv(session, buffer, length, 0);
        if (bytes_read <= 0)
        {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
            	LOG_E("receive data timeout.");
                return -WEBCLIENT_TIMEOUT; /* recv timeout */
            }
            else
            {
            	if(session->tls_socket)
            	{
            		HAL_SSL_Destroy(session->tls_socket);
            		session->tls_socket = 0;
            	}
            	else
            	{
            		cmClose(session->socket);
            		session->socket = -1;
            	}
                return 0;
            }
        }

        session->chunk_offset += bytes_read;
        if (session->chunk_offset >= session->chunk_sz)
        {
            webclient_next_chunk(session);
        }

        return bytes_read;
    }

    if (session->content_length > 0)
    {
        if (length > session->content_remainder)
        {
            length = session->content_remainder;
        }

        if (length == 0)
        {
            return 0;
        }
    }

    LOG_E("left =%d.", length);
    left = length;
    do
    {
        bytes_read = webclient_recv(session, (void *)((char *)buffer + total_read), left, 0);
        if (bytes_read <= 0)
        {
            LOG_E("receive data error(%d).", bytes_read);

            if (total_read)
            {
                break;
            }
            else
            {
                if (errno == EWOULDBLOCK || errno == EAGAIN)
                {
                    LOG_E("receive data timeout.");
                    return -WEBCLIENT_TIMEOUT;
                }
                else
                {
                	if(session->tls_socket)
                	{
                		HAL_SSL_Destroy(session->tls_socket);
                		session->tls_socket = 0;
                	}
                	else
                	{
                		cmClose(session->socket);
                		session->socket = -1;
                	}
                    return 0;
                }
            }
        }

        left -= bytes_read;
        total_read += bytes_read;
    }
    while (left);

    if (session->content_length > 0)
    {
        session->content_remainder -= total_read;
    }

    return total_read;
}

/**************************************************************************
** 函数名：webclient_write
** 功能描述：发送数据到HTTP服务器
** 作者：邵温财
** 日期：2020.02.20
** 返回：>0 成功发送的字节数        =0 连接断开         <0发送错误
***************************************************************************/
int webclient_write(struct webclient_session *session, const void *buffer, size_t length)
{
    int bytes_write = 0;
    int total_write = 0;
    int left = length;

    if (session->socket < 0 && session->tls_socket == 0)
    {
        return -WEBCLIENT_DISCONNECT;
    }

    if (length == 0)
    {
        return 0;
    }

    do
    {
        bytes_write = webclient_send(session, (void *)((char *)buffer + total_write), left, 0);
        if (bytes_write <= 0)
        {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                if (total_write)
                {
                    return total_write;
                }
                continue;
            }
            else
            {
            	if(session->tls_socket)
            	{
            		HAL_SSL_Destroy(session->tls_socket);
            		session->tls_socket = 0;
            	}
            	else
            	{
            		cmClose(session->socket);
            		session->socket = -1;
            	}

                if (total_write == 0)
                {
                    return -WEBCLIENT_DISCONNECT;
                }
                break;
            }
        }

        left -= bytes_write;
        total_write += bytes_write;
    }
    while (left);

    return total_write;
}

/**************************************************************************
** 函数名：webclient_close
** 功能描述：关闭会话 释放资源
** 作者：邵温财
** 日期：2020.02.20
***************************************************************************/
int webclient_close(struct webclient_session *session)
{
    webclient_clean(session);

    if (session->header && session->header->buffer)
    {
        web_free(session->header->buffer);
        session->header->buffer = NULL;
    }

    if (session->header)
    {
        web_free(session->header);
        session->header = NULL;
    }

    if (session)
    {
        web_free(session);
        session = NULL;
    }

    return 0;
}



/**************************************************************************
** 函数名：webclient_response
** 功能描述：得到资源请求返回的数据
** 作者：邵温财
** 日期：2020.02.20
** 返回：成功读取的字节数   
***************************************************************************/
int webclient_receive_response(struct webclient_session *session, void *buf,size_t bufSize,size_t *resp_len)
{
    unsigned char *buf_ptr;
    int length, total_read = 0;
    
    if(buf == NULL)
    {
    	return 0;
    }
    
    LOG_E("session->content_length=%d.",session->content_length);
    
    if (session->content_length < 0)
    {
        total_read = 0;
        
        if(bufSize < WEBCLIENT_RESPONSE_BUFSZ)
        {
        	return 0;
        }
        
        while (1)
        {
        	if(total_read > bufSize-WEBCLIENT_RESPONSE_BUFSZ)break;
        		
            buf_ptr = (unsigned char *) buf + total_read;
            
            length = webclient_read(session, buf_ptr,WEBCLIENT_RESPONSE_BUFSZ);
            
            if (length <= 0)break;

            total_read += length;
        }
    }
    else
    {
        int result_sz;

        result_sz = session->content_length;
        if(bufSize < result_sz)
        {
        	result_sz = bufSize;
        }
        
        buf_ptr = (unsigned char *) buf;
        
        for (total_read = 0; total_read < result_sz;)
        {
            length = webclient_read(session, buf_ptr, result_sz - total_read);
            
            if (length <= 0)break;

            buf_ptr += length;
            
            total_read += length;
        }
    }

    return total_read;
}
