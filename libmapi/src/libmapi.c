/*
 * Author:	Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

/**
 * \mainpage Monitoring API (MAPI) Library
 * 
 * \section Author Author
 * 
 * MAPI has been written by Konstantinos Xinidis. You can contact me by e-mail on xinidis@csd.uoc.gr. 
 * I'd be happy to get any feedback that you may have on MAPI, including proper documentation, 
 * bug reports, enhancements and suggestions for these, and bug fixes, of course.
 * 
 * \section License License
 * 
 * MAPI is Open Source software released under the GNU General Public License.
 *
 */

/** \file 
 *
 * This file contains the interface that libmapi provides.
 *
 * \author Konstantinos Xinidis, <xinidis@csd.uoc.gr>
 *
 */

#include <mapi.h>
#include "linux/mapi-linux.h"

/** \brief Is used for creating a new network flow of packets that match condition \c filter_condition. 
 * 	
 * Network flows come in three modes as defined by argument mode: \c RAW, \c COOKED and \c HIERARCHICAL. 
 * In the \c RAW mode, the network flow consists of all network packets that satisfy the condition 
 * \c filter_condition. These may include fragmented packets, retransmitted packets, out-of-order 
 * packets, etc. The packets in the \c RAW mode are stored (and transmitted to the monitoring application) 
 * unmodified in the order of their arrival. In the \c COOKED mode, on the other hand, the incoming 
 * packets (that satisfy the condition \c filter_condition) are processed according to the protocol 
 * stated in the packet header. Such protocols maybe TCP/IP, UDP/IP, etc. For example when processing 
 * TCP/IP packets in \c COOKED mode, fragmented IP packets are combined, retransmitted packets
 * are filtered out, and in general packets are reassembled into a data stream. That is, in the 
 * \c COOKED mode the incoming network packets are turned into the data stream that would normally 
 * be presented to the socket layer. In the \c COOKED mode, users also define a block size, which is 
 * the size of the chunk of the data they want to receive. For example, if the user defines a flow 
 * in \c COOKED mode and a block size of 64 Kbytes, the system will reassemble all the received packets 
 * into a data stream and chop the data stream into 64-Kbyte-large chunks. These chucks will be returned 
 * to the monitoring applications when they request them. If the user does not define a block size, a
 * default block size is used. The block size along with all options of a network flow can 
 * be adjusted using the \link mapi_set_flow_option \endlink. One the monitoring application set all the options, 
 * it will connect (\link mapi_connect \endlink) to the network flow in order to start receiving network packets 
 * and/or network statistics. Besides creating a network flow, monitoring applications may also destroy the 
 * network flow when they are no longer interested in monitoring this flow (\link mapi_destroy_flow \endlink).
 * After closing a network flow, the system releases all the structures that have been allocated for the 
 * network flow. Network flows allow users to organize the packets they are interested in monitoring 
 * into separate streams, and thus be able to treat them differently. 
 *
 * \b Example:
 *
 * In most cases, users are interested in monitoring several sources of packets, and for each source of packet 
 * they are probably interested in monitoring different properties. Assume for the moment network administrators 
 * who may be interested in several network flows at-a-time: they may be interested in observing the bandwidth 
 * consumed by peer-to-peer file sharing systems that may be running, while at the same time they may be interested in 
 * monitoring for Denial of Service attacks on their web server. On top of that, their site may also 
 * participate in a trajectory sampling experiment that samples and records a small percentage of packets. 
 * Organizing these three different monitoring activities as separate network flows, allows users 
 * (i.e. the administrators) to identify them, to isolate them, and to treat them differently. Even more 
 * important than neatly separating different monitoring activities, network flows allow users to focus 
 * on different activities at different times. For example, during a DDoS attack, an administrator may decide 
 * to ignore the applications that measure the bandwidth usage of peer-to-peer systems and launch more
 * fine-grain DDoS attack monitoring activities in order to pinpoint and isolate the the attack. When the DDoS 
 * attack is over,the administrator may decide to stop some of these fine-grain DDoS attack monitoring 
 * activities and resume its usual peer-to-peer bandwidth usage monitoring.
 *	
 * \attention The \c HIERARCHICAL network flows can not send packets to the monitoring application.So, 
 * 	      the functions \link mapi_get_next_packet \endlink and \link mapi_loop \endlink are meaningless.
 *	
 * @param ifname		The name of the network interface from which packets will be read e.g "eth0".
 * 				If NULL then the first available interface is choosen.If no such interface exists
 * 				the function will fail.
 * @param filter_condition	The condition to match e.g "port 80". The condition bust be in a format that
 * 				tcpdump understands.
 * @param mode			The mode can be \c RAW, \c COOKED or \c HIERARCHICAL.
 *
 * @return 		If successful, the function returns a non-NULL network flow descriptor.
 *			If unsuccessful, the function returns NULL.
 */

mapi_flow_t *mapi_create_flow(char *ifname,char *filter_condition,mode_t mode)
{
#ifdef HAVE_LINUX	
	return linux_mapi_create_flow(ifname,filter_condition,mode);
#else
#endif
}

/** \brief Requestor starts receiving information from this network flow.
 *
 * This function may fail depending on the requestors privileges and
 * requirements.
 *
 * @param mp	The network flow to connect.
 *
 * @return	If successful, the function returns 0.
 * 		If unsuccessful, the function returns 1.
 */ 

int mapi_connect(mapi_flow_t *mp)
{
#ifdef HAVE_LINUX	
	return linux_mapi_connect(mp);
#else 
#endif
}

/** \brief Is used to configure network flow.
 *
 * @pre			The network flow must not be connected. If it is already connected
 * 			the function will fail.
 * 
 * @param mp		The network flow whose options want to change.
 * @param option	The option to set.
 * @param arg		The new value to set to the option.
 * 
 * @return	If successful, the function returns 0.
 * 		If unsuccessful, the function returns 1.
 */ 

int mapi_set_flow_option(mapi_flow_t *mp,int option,void *arg)
{
#ifdef HAVE_LINUX	
	return linux_mapi_set_flow_option(mp,option,arg);
#else
#endif
}

/** \brief Is used to get the configuration of the network flow.
 *
 * @param mp		The network flow whose options want to change.
 * @param option	The option to get.
 * 
 * @return		A pointer which points to the value of the option.
 *
 * \warning		If you change the value the pointer points to then the
 * 			option will also change.
 */ 

void *mapi_get_flow_option(mapi_flow_t *mp,int option)
{
#ifdef HAVE_LINUX	
	return linux_mapi_get_flow_option(mp,option);
#else
#endif
}

/** \brief Applies function with the requested \c function_id to all packets of
 * the network flow \c mp.
 *
 * Besides the neat arrangement of packets, network flows allow users to treat packets 
 * that belong to separate network flows in different ways. For example, a user may be 
 * interested in logging all packets of one flow (e.g. to record an intrusion attempt), 
 * in just counting the packets and their lengths of a second flow (e.g. to count the 
 * bandwidth usage of an application), and in sampling the packets of a third flow 
 * (e.g. to find the most frequent network destinations). The abstraction of the network 
 * flow allows the user to clearly communicate to the underlying monitoring system these 
 * different operations. To enable users to communicate these different requirements, MAPI 
 * enable users to associate functions with flows. This association implies that the functions 
 * will be applied to each packet of a flow. For example, a user may only want to count the packets 
 * that belong to one particular flow. In this case, the user will associate a counter function with 
 * this flow. Each packet that arrives in the flow will invoke this function which will just 
 * increment a counter. As another example consider a user who wants to sample every tenth packet 
 * of a network flow. Then, (s)he will be able to associate a sampling function with this flow. 
 * Each arriving packet will invoke this function, which will discard nine out of every 10 packets. 
 * 
 * @param mp		The network flow to which function will be applied.
 * @param function_id	The unique number that distinguishes the function to apply.
 * @param args		The arguments that this function may require.
 *
 * @return		If successful returns a pointer to a struct \link mapi_func \endlink
 * 			which is used for later reference e.g read results.Otherwise it 
 * 			returns NULL.
 *
 * \warning 		After this call application can free \c args if it wants.
 */

mapi_func_t *mapi_apply_function(mapi_flow_t *mp,int function_id,void *args)
{
#ifdef HAVE_LINUX	
	return linux_mapi_apply_function(mp,function_id,args);
#else
#endif
}

/** \brief Removes function previously applied to network flow \c mp.
 *
 * If the network flow has no such function applied earlier the function will fail.
 * 
 * @param mp		The network flow from which function will be removed.
 * @param func		The pointer returned by \link mapi_apply_function \endlink.
 *
 * @return		If successful, the function returns 0.
 * 			If unsuccessful, the function returns 1.
 */

int mapi_remove_function(mapi_flow_t *mp,mapi_func_t *func)
{
#ifdef HAVE_LINUX	
	return linux_mapi_remove_function(mp,func);
#else
#endif
}

/** \brief Resets the statistics kept from the network flow \c mp for the
 * 	   the function \c func.
 *
 * If the network flow has no such function applied earlier the function will fail.
 * 
 * @param mp		The network flow to which function was applied.
 * @param func		The pointer returned by \link mapi_apply_function \endlink.
 *
 * @return		If successful, the function returns 0.
 * 			If unsuccessful, the function returns 1.
 */

int mapi_reset_function(mapi_flow_t *mp,mapi_func_t *func)
{
#ifdef HAVE_LINUX	
	return linux_mapi_reset_function(mp,func);
#else
#endif
}

/** \brief Receives statistics or any kind of results that have been computed by the
 * 	   application of the function \c func to the packets of network flow \c mp.
 * 	  
 * The results will be returned in a structure pointed to by pointer \c results.	  
 *
 * If the network flow has no such function applied earlier the function will fail.
 * 
 * @param mp		The network flow to which function was applied.
 * @param func		The pointer returned by \link mapi_apply_function \endlink.
 * @param results	The structure which will be filled with the results.
 * 
 * @return		If successful, the function returns 0.
 * 			If unsuccessful, the function returns 1.
 */

int mapi_read_results(mapi_flow_t *mp,mapi_func_t *func,void *results)
{
#ifdef HAVE_LINUX	
	return linux_mapi_read_results(mp,func,results);
#else
#endif
}

/** \brief Reads the next packet.
 *
 *  Returns a pointer to the next available packet for network flow \c mp.
 *  If no such packet exists, the call blocks until such a packet is received.
 *  The packet is of type struct \link mapi_packet \endlink. 
 *
 *  \attention This function is meaningless if called for an \c HIERARCHICAL 
 *  	       network flow.
 *  
 * @param mp	The network flow from which we want to read the packet.
 *
 * @return 	If succesfull returns a pointer to the packet else NULL.
 */

mapi_packet_t *mapi_get_next_packet(mapi_flow_t *mp)
{
#ifdef HAVE_LINUX	
	return linux_mapi_get_next_packet(mp);
#else
#endif
}

/** \brief Registers a handler to be applied to packets. 
 * 
 *  If application do not want to block in the process of receiving network packets from 
 *  a network flow using \link mapi_get_next_packet \endlink call, it may invoke the 
 *  \c mapi_loop call which invokes the \c handler after it has received a packet from 
 *  network flow \c mp. The \c handler is invoked for the next \c cnt packets of network 
 *  flow \c mp. If \c cnt is -1, \c handler is invoked for all future packets of network 
 *  flow \c mp. 
 *
 * @see mapi_handler
 *
 * \attention Non blocking call.
 * 
 * @param mp		The network flow to which the handler is applied.
 * @param cnt		The handler will be applied to \c cnt packets.If -1 \c handler is 
 * 			invloked for all future packets.
 * @param handler	The handler to apply to received packets.
 * @param user_data	These data is passed to the handler.
 *
 * @return		If successful, the function returns 0.
 * 			If unsuccessful, the function returns 1.
 */ 

int mapi_loop(mapi_flow_t *mp,int cnt,mapi_handler handler,void *user_data)
{
#ifdef HAVE_LINUX	
	return linux_mapi_loop(mp,cnt,handler,user_data);
#else
#endif
}

/** \brief Finds the next expired subflow.
 *
 * Returns a pointer to the next expired subflow.
 * If no such subflow exists, the call blocks until a subflow expires. 
 * 
 * The subflow is of type struct \link mapi_subflow \endlink. 
 *
 * \attention This function is meaningfull only for \c HIERARCHICAL
 *	      network flows. 
 * 
 * @param mp	The network flow.
 *
 * @return 	If succesfull returns a pointer to the subflow else NULL.
 */

mapi_subflow_t *mapi_get_next_subflow(mapi_flow_t *mp)
{
#ifdef HAVE_LINUX	
	return linux_mapi_get_next_subflow(mp);
#else
#endif
}

/** \brief Registers a handler to be applied to expired subflows. 
 * 
 *  If application do not want to block in the process of receiving expired subflows 
 *  using \link mapi_get_next_subflow \endlink call, it may invoke the 
 *  \c mapi_subflow_loop call which invokes the \c handler after it has received an
 *  expired subflow from network flow \c mp. The \c handler is invoked for the next
 *  \c cnt expired subflows of network flow \c mp. If \c cnt is -1, \c handler is invoked 
 *  for all future expired subflows of network flow \c mp. 
 *
 * @see mapi_subflow_handler
 *
 * \attention Non blocking call.
 * 
 * @param mp		The network flow to which the handler is applied.
 * @param cnt		The handler will be applied to \c cnt expired subflows.
 * 			If -1 \c handler is invloked for all future expired subflows.
 * @param handler	The handler to apply to expired subflows.
 * @param user_data	These data is passed to the handler.
 *
 * @return		If successful, the function returns 0.
 * 			If unsuccessful, the function returns 1.
 */ 

int mapi_subflow_loop(mapi_flow_t *mp,int cnt,mapi_subflow_handler handler,void *user_data)
{
#ifdef HAVE_LINUX	
	return linux_mapi_subflow_loop(mp,cnt,handler,user_data);
#else
#endif
}

/** \brief Saves all received packets to the file descriptor \c filed. 
 * 
 * @param mp		The network flow.
 * @param filed		The open file descriptor.
 *
 * @return		If successful, the function returns 0.
 * 			If unsuccessful, the function returns 1.
 */ 

int mapi_save(mapi_flow_t *mp,int filed)
{
#ifdef HAVE_LINUX	
	return linux_mapi_save(mp,filed);
#else
#endif
}

/** \brief Is used to deallocate resources. After that network
 * 	   flow \c mp must not be used.
 * 
 * @param mp		The network flow to destroy.
 */ 

void mapi_destroy_flow(mapi_flow_t *mp)
{
#ifdef HAVE_LINUX	
	linux_mapi_destroy_flow(mp);
#else
#endif
}
