#ifndef __MAPI_H
#define __MAPI_H

#include <sys/types.h>

#define MAPI_VERSION_MAJOR 0
#define MAPI_VERSION_MINOR 1

typedef struct mapi_filter mapi_filter_t;

/** \brief The three available modes that network flows support.
 */

typedef enum
{
	RAW,
	COOKED,
	HIERARCHICAL
	
} flow_mode_t;

enum
{
	ADD,
	REMOVE,
	READ_RESULTS,
	RESET,
	ADD_ASYNC,
	REMOVE_ASYNC

} actions_t;

typedef struct mapi_options
{
	u_char no_copy;
	u_int32_t rcv_buf_size;
	
	struct
	{
		u_int size;
		u_int len;

	} packet;

	struct 
	{
		u_int bytes;
		u_int timeout;
		u_int max_duration;
		u_int max_subflows_to_copy;

	} subflow;
	
} mapi_options_t;

/** \brief This struct represents a network packet.
 *
 * Fields:
 * 
 *  - data	u_char \c * pointer which points to a sequence of bytes.
 *  		This sequence starts with a header and continues with the 
 *  		network packet itself.
 *  		
 *  - data_len	The number of bytes read. This can be smaller than \c real_len 
 *  		for a number of reasons. For example, because the packet was 
 *  		too large to be copied to array \c data.
 *  		
 *  - real_len	The actual length of the packet.
 * 
 */
typedef struct mapi_packet
{
	u_char *data;
	u_int data_len;
	u_int real_len;

} mapi_packet_t;

/** \brief This struct represents an expired subflow.
 *
 * @see subflow
 */
typedef struct mapi_subflow
{
	struct subflow *sbf;
	
} mapi_subflow_t;

/** \brief This struct represents a network flow.
 *
 * Normally application developer do not need to know nothing about
 * the fields of this struct.
 * 
 */
typedef struct mapi_flow
{
	int fd;
	
	char *ifname;
	char *condition;
	
	mapi_packet_t packet;
	mapi_subflow_t subflow;
	
	u_char promisc_on;

	flow_mode_t mode;
	
	union
	{
		struct 
		{
			struct cook_ip_struct *ip;
			struct cook_udp_struct *udp;
			struct cook_tcp_struct *tcp;
			
		} cooked;
		
		struct
		{
			struct subflow_ioctl_struct *subflow_io;
			int last_index;

		} hierarchical;
		
	} mode_ptr ;
	
	mapi_filter_t *filter;
	
	mapi_options_t options;
	
} mapi_flow_t;


/** \brief This struct is a help struct for the handling of applied functions.
 *
 * Normally application developer do not need to know nothing about
 * the fields of this struct.
 * 
 */
typedef struct mapi_func
{
	int function_id;
	void *args;
	
} mapi_func_t;


/** \brief The available network flow options.
 */
enum 
{
	PACKET_SIZE,
	PACKET_LENGTH,
	SUBFLOW_TIMEOUT,
	SUBFLOW_MAX_DURATION,
	SUBFLOW_MAX_SUBFLOWS_TO_COPY,
	NO_COPY,
	CONDITION,
	RCVBUFSIZE
};

static inline void set_default_options(mapi_options_t *options)
{
	options->no_copy = 0;	
	options->packet.size = 64*1024;	
	options->packet.len = 64;
	
	options->subflow.bytes = 32*1024;	
	options->subflow.timeout = 1;		//secs
	options->subflow.max_duration = 15*60;	//secs
	options->subflow.max_subflows_to_copy = 1000;
}

/** \brief The callback to be applied to all packets that reach application.
 *
 * Args:
 * 
 *  - a pointer to a struct \link mapi_packet \endlink.
 *  - a pointer to private data which is passed from \link mapi_loop \endlink.
 */
typedef void (*mapi_handler)(mapi_packet_t *packet,void *user_data);

/** \brief The callback to be applied to all expired subflows.
 *
 * Args:
 * 
 *  - a pointer to a struct \link mapi_subflow \endlink.
 *  - a pointer to private data which is passed from \link mapi_subflow_loop \endlink.
 */
typedef void (*mapi_subflow_handler)(mapi_subflow_t *subflow,void *user_data);

mapi_flow_t *mapi_create_flow(char *ifname,char *filter_condition,flow_mode_t mode);
int mapi_connect(mapi_flow_t *mp);
int mapi_set_flow_option(mapi_flow_t *mp,int option,void *arg);
void *mapi_get_flow_option(mapi_flow_t *mp,int option);
mapi_func_t *mapi_apply_function(mapi_flow_t *mp,int function_id,void *args);
int mapi_remove_function(mapi_flow_t *mp,mapi_func_t *func);
int mapi_reset_function(mapi_flow_t *mp,mapi_func_t *func);
int mapi_read_results(mapi_flow_t *mp,mapi_func_t *func,void *results);
mapi_packet_t *mapi_get_next_packet(mapi_flow_t *mp);
int mapi_loop(mapi_flow_t *mp,int cnt,mapi_handler handler,void *user_data);
mapi_subflow_t *mapi_get_next_subflow(mapi_flow_t *mp);
int mapi_subflow_loop(mapi_flow_t *mp,int cnt,mapi_subflow_handler handler,void *user_data);
int mapi_save(mapi_flow_t *mp,int filed);
void mapi_destroy_flow(mapi_flow_t *mp);

#endif /* __MAPI_H */
