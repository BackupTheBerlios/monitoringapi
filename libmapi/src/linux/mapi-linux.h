#ifndef __MAPILINUX_H
#define __MAPILINUX_H

mapi_flow_t *linux_mapi_create_flow(char *ifname,char *filter_condition,flow_mode_t mode);
int linux_mapi_connect(mapi_flow_t *mp);
int linux_mapi_set_flow_option(mapi_flow_t *mp,int option,void *arg);
void *linux_mapi_get_flow_option(mapi_flow_t *mp,int option);
mapi_func_t *linux_mapi_apply_function(mapi_flow_t *mp,int function_id,void *args);
int linux_mapi_remove_function(mapi_flow_t *mp,mapi_func_t *func);
int linux_mapi_reset_function(mapi_flow_t *mp,mapi_func_t *func);
int linux_mapi_read_results(mapi_flow_t *mp,mapi_func_t *func,void *results);
mapi_packet_t *linux_mapi_get_next_packet(mapi_flow_t *mp);
int linux_mapi_loop(mapi_flow_t *mp,int cnt,mapi_handler handler,void *user_data);
mapi_subflow_t *linux_mapi_get_next_subflow(mapi_flow_t *mp);
int linux_mapi_subflow_loop(mapi_flow_t *mp,int cnt,mapi_subflow_handler handler,void *user_data);
int linux_mapi_save(mapi_flow_t *mp,int filed);
void linux_mapi_destroy_flow(mapi_flow_t *mp);

#endif /* __MAPILINUX_H */
