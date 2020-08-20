#ifndef _HTTP_H_
#define _HTTP_H_

#include "../../../../h/include.h"
#include "webclient.h"


int webclient_get_file(const char* URI, const char* filename);
int webclient_request(const char *URI, const char *header, const void *post_data, 
					  size_t data_len,void *response,size_t responseBufSize, size_t *resp_len);
int webclient_post_file(const char* URI, const char* filename,const char* form_data);


#endif
