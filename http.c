#include "http.h"


/**************************************************************************
** 函数名：webclient_get_file
** 功能描述：发送GET请求,将应答数据保存到文件中
** 参数：URI 服务器资源地址
** 参数：filename 保存应答数据到此文件中
** 作者：邵温财
** 日期：2020.06.22
** 返回：=0 成功       !=0 失败
***************************************************************************/
int webclient_get_file(const char* URI, const char* filename)
{
    int fd = -1, rc = WEBCLIENT_OK;
    size_t offset;
    int length, total_length = 0;
    unsigned char *ptr = NULL;
    struct webclient_session* session = NULL;
    int resp_status = 0;

    session = webclient_session_create(WEBCLIENT_HEADER_BUFSZ);
    if(session == NULL)
    {
        rc = -WEBCLIENT_NOMEM;
        goto __exit;
    }

    if ((resp_status = webclient_get(session, URI)) != 200)
    {
        LOG_E("get file failed, wrong response: %d (-0x%X).", resp_status, resp_status);
        rc = -WEBCLIENT_ERROR;
        goto __exit;
    }

    fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 777);
    if (fd < 0)
    {
        LOG_E("get file failed, open file(%s) error.", filename);
        rc = -WEBCLIENT_ERROR;
        goto __exit;
    }

    ptr = (unsigned char *) web_malloc(WEBCLIENT_RESPONSE_BUFSZ);
    if (ptr == NULL)
    {
        LOG_E("get file failed, no memory for response buffer.");
        rc = -WEBCLIENT_NOMEM;
        goto __exit;
    }

    if (session->content_length < 0)
    {
        while (1)
        {
            length = webclient_read(session, ptr, WEBCLIENT_RESPONSE_BUFSZ);
            if (length > 0)
            {
                write(fd, ptr, length);
                total_length += length;
            }
            else
            {
                break;
            }
        }
    }
    else
    {
        for (offset = 0; offset < (size_t) session->content_length;)
        {
            length = webclient_read(session, ptr,
                    session->content_length - offset > WEBCLIENT_RESPONSE_BUFSZ ?
                            WEBCLIENT_RESPONSE_BUFSZ : session->content_length - offset);

            if (length > 0)
            {
                write(fd, ptr, length);
                total_length += length;
            }
            else
            {
                break;
            }

            offset += length;
        }
    }

    if (total_length)
    {
        LOG_D("save %d bytes.", total_length);
    }

__exit:
    if (fd >= 0)
    {
        close(fd);
    }

    if (session != NULL)
    {
        webclient_close(session);
    }

    if (ptr != NULL)
    {
        web_free(ptr);
    }

    return rc;
}

/**************************************************************************
** 函数名：webclient_get_file
** 功能描述：发送请求(GET/POST)到服务器 并得到应答数据.
** 参数：URI 服务器资源地址
** 参数：header = NULL: use default header data
**           != NULL: user custom header data
** 作者：邵温财
** 日期：2020.06.22
** 返回：>=0 成功       <0 失败
***************************************************************************/
int webclient_request(const char *URI, const char *header, const void *post_data, 
					  size_t data_len, void *response,size_t responseBufSize,size_t *resp_len)
{
    struct webclient_session *session = NULL;
    int rc = WEBCLIENT_OK;
    int totle_length = 0;

    if (post_data == NULL && response == NULL)
    {
        LOG_E("request get failed, get response data cannot be empty.");
        return -WEBCLIENT_ERROR;
    }

    if ((post_data != NULL) && (data_len == 0))
    {
        LOG_E("input post data length failed");
        return -WEBCLIENT_ERROR;
    }

    if ((response != NULL && resp_len == NULL) || 
        (response == NULL && resp_len != NULL))
    {
        LOG_E("input response data or length failed");
        return -WEBCLIENT_ERROR;
    }

    if (post_data == NULL)
    {
        /* send get request */
        session = webclient_session_create(WEBCLIENT_HEADER_BUFSZ);
        if (session == NULL)
        {
            rc = -WEBCLIENT_NOMEM;
            goto __exit;
        }

        if (header != NULL)
        {
            char *header_str, *header_ptr;
            int header_line_length;

            for(header_str = (char *)header; (header_ptr = strstr(header_str, "\r\n")) != NULL; )
            {
                header_line_length = header_ptr + strlen("\r\n") - header_str;
                webclient_header_fields_add(session, "%.*s", header_line_length, header_str);
                header_str += header_line_length;
            }
        }

        if (webclient_get(session, URI) != 200)
        {
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }

        totle_length = webclient_receive_response(session, response,responseBufSize,resp_len);
        if (totle_length <= 0)
        {
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }
    }
    else
    {
        /* send post request */
        session = webclient_session_create(WEBCLIENT_HEADER_BUFSZ);
        if (session == NULL)
        {
            rc = -WEBCLIENT_NOMEM;
            goto __exit;
        }

        if (header != NULL)
        {
            char *header_str, *header_ptr;
            int header_line_length;

            for(header_str = (char *)header; (header_ptr = strstr(header_str, "\r\n")) != NULL; )
            {
                header_line_length = header_ptr + strlen("\r\n") - header_str;
                webclient_header_fields_add(session, "%.*s", header_line_length, header_str);
                header_str += header_line_length;
            }
        }

        if (strstr(session->header->buffer, "Content-Length") == NULL)
        {
            webclient_header_fields_add(session, "Content-Length: %d\r\n", strlen(post_data));
        }

        if (strstr(session->header->buffer, "Content-Type") == NULL)
        {
            webclient_header_fields_add(session, "Content-Type: application/octet-stream\r\n");
        }

        if (webclient_post(session, URI, post_data, data_len) != 200)
        {
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }

        totle_length = webclient_receive_response(session, response,responseBufSize ,resp_len);
        if (totle_length <= 0)
        {
            rc = -WEBCLIENT_ERROR;
            goto __exit;
        }
    }

__exit:
    if (session)
    {
        webclient_close(session);
        session = NULL;
    }

    if (rc < 0)
    {
        return rc;
    }
    
    *resp_len = totle_length;
    
    return totle_length;
}


/**************************************************************************
** 函数名：webclient_post_file
** 功能描述：推送文件数据到服务器.
** 参数：URI 服务器资源地址
** 参数：form_data 推送文件的格式  传入字符串
** 作者：邵温财
** 日期：2020.06.22
** 返回：>=0 成功       <0 失败
***************************************************************************/
int webclient_post_file(const char* URI, const char* filename,const char* form_data)
{
    size_t length;
    char boundary[60];
    int fd = -1, rc = WEBCLIENT_OK;
    char *header = NULL, *header_ptr;
    unsigned char *buffer = NULL, *buffer_ptr;
    struct webclient_session* session = NULL;
    int resp_data_len = 0;

    fd = open(filename, O_RDONLY, 0);
    if (fd < 0)
    {
        LOG_D("post file failed, open file(%s) error.", filename);
        rc = -WEBCLIENT_FILE_ERROR;
        goto __exit;
    }

    /* get the size of file */
    length = (size_t)lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    buffer = (unsigned char *) web_calloc(1, WEBCLIENT_RESPONSE_BUFSZ);
    if (buffer == NULL)
    {
        LOG_D("post file failed, no memory for response buffer.");
        rc = -WEBCLIENT_NOMEM;
        goto __exit;
    }

    header = (char *) web_calloc(1, WEBCLIENT_HEADER_BUFSZ);
    if (header == NULL)
    {
        LOG_D("post file failed, no memory for header buffer.");
        rc = -WEBCLIENT_NOMEM;
        goto __exit;
    }
    header_ptr = header;

    /* build boundary */
    snprintf(boundary, sizeof(boundary), "----------------------------%012d", tickGet());

    /* build encapsulated mime_multipart information*/
    buffer_ptr = buffer;
    /* first boundary */
    buffer_ptr += snprintf((char*) buffer_ptr,
            WEBCLIENT_RESPONSE_BUFSZ - (buffer_ptr - buffer), "--%s\r\n", boundary);
    buffer_ptr += snprintf((char*) buffer_ptr,
            WEBCLIENT_RESPONSE_BUFSZ - (buffer_ptr - buffer),
            "Content-Disposition: form-data; %s\r\n", form_data);
    buffer_ptr += snprintf((char*) buffer_ptr,
            WEBCLIENT_RESPONSE_BUFSZ - (buffer_ptr - buffer),
            "Content-Type: application/octet-stream\r\n\r\n");
    /* calculate content-length */
    length += buffer_ptr - buffer;
    length += strlen(boundary) + 8; /* add the last boundary */

    /* build header for upload */
    header_ptr += snprintf(header_ptr,
            WEBCLIENT_HEADER_BUFSZ - (header_ptr - header),
            "Content-Length: %d\r\n", length);
    header_ptr += snprintf(header_ptr,
            WEBCLIENT_HEADER_BUFSZ - (header_ptr - header),
            "Content-Type: multipart/form-data; boundary=%s\r\n", boundary);

    session = webclient_session_create(WEBCLIENT_HEADER_BUFSZ);
    if(session == NULL)
    {
        rc = -WEBCLIENT_NOMEM;
        goto __exit;
    }

    strncpy(session->header->buffer, header, strlen(header));
    session->header->length = strlen(session->header->buffer);

    rc = webclient_post(session, URI, NULL, 0);
    if(rc < 0)
    {
        goto __exit;
    }

    /* send mime_multipart */
    webclient_write(session, buffer, buffer_ptr - buffer);

    /* send file data */
    while (1)
    {
        length = read(fd, buffer, WEBCLIENT_RESPONSE_BUFSZ);
        if (length <= 0)
        {
            break;
        }

        webclient_write(session, buffer, length);
    }

    /* send last boundary */
    snprintf((char*) buffer, WEBCLIENT_RESPONSE_BUFSZ, "\r\n--%s--\r\n", boundary);
    webclient_write(session, buffer, strlen(boundary) + 8);

    extern int webclient_handle_response(struct webclient_session *session);
    if( webclient_handle_response(session) != 200)
    {
        rc = -WEBCLIENT_ERROR;
        goto __exit;
    }

    resp_data_len = webclient_content_length_get(session);
    if (resp_data_len > 0)
    {
        int bytes_read = 0;

        memset(buffer, 0x00, WEBCLIENT_RESPONSE_BUFSZ);
        do
        {
            bytes_read = webclient_read(session, buffer,
                resp_data_len < WEBCLIENT_RESPONSE_BUFSZ ? resp_data_len : WEBCLIENT_RESPONSE_BUFSZ);
            if (bytes_read <= 0)
            {
                break;
            }
            resp_data_len -= bytes_read;
        } while(resp_data_len > 0);
    }

__exit:
    if (fd >= 0)
    {
        close(fd);
    }

    if (session != NULL)
    {
        webclient_close(session);
    }

    if (buffer != NULL)
    {
        web_free(buffer);
    }

    if (header != NULL)
    {
        web_free(header);
    }

    return rc;
}
