/******************************************************************************
 *
 *  This module implements Linux Ethernet statistics for individual Ethernet
 *  devices.
 *
 *  The code has been tested with SLES 9, SLES 10, SLES 11, RHEL 4 and RHEL 5
 *  on different systems.
 *
 *  Written by Michael Perzl (michael@perzl.org)
 *
 *  Version 1.3, Jun 17, 2016
 *
 *  Version 1.3:  Jun 17, 2016
 *                - fixed the segmentation faults
 *
 *  Version 1.2:  Oct 21, 2013
 *                - changed BUFFSIZE to 65536
 *
 *  Version 1.1:  Jul 16, 2013
 *                - fixed the segmentation faults
 *
 *  Version 1.0:  Jun 27, 2011
 *                - initial version
 *
 ******************************************************************************/

/*
 * The ganglia metric "C" interface, required for building DSO modules.
 */

#include <gm_metric.h>


#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>
#include <setjmp.h>

#include <apr_strings.h>

#include "interface.h"
#include "libmetrics.h"
#include "gm_file.h"


#undef DEBUG
#define USE_SIGNALS

#define MIN_THRESHOLD 5.0

#define MAX_BUF_SIZE 1024


static time_t boottime;


#ifndef BUFFSIZE
#define BUFFSIZE 65536
#endif


struct netif_devices_t {
   int enabled;
   double last_read;
   double threshold;
   char devName[MAX_G_STRING_SIZE];
};

typedef struct netif_devices_t netif_devices_t;


struct net_perf_data_t {
   double last_value;
   double curr_value;
   long long last_total_value;
};

typedef struct net_perf_data_t net_perf_data_t;


static unsigned int netif_count = 0;

static netif_devices_t *netif_devices = NULL;

static net_perf_data_t *netif_bytes_received = NULL;
static net_perf_data_t *netif_bytes_sent = NULL;
static net_perf_data_t *netif_pkts_received = NULL;
static net_perf_data_t *netif_pkts_sent = NULL;

static apr_pool_t *pool;

static apr_array_header_t *metric_info = NULL;

static int Signal_devIndex = -1;

static jmp_buf my_jumpbuf;



extern timely_file proc_net_dev;



#ifdef USE_SIGNALS
/* Signal handler */
void my_sig_handler( int sig_num )
{
   char msg[512];


   switch( sig_num )
   {
/* the entstat command took too long - don't call entstat for that adapter anymore */
      case SIGALRM: netif_devices[Signal_devIndex].enabled = FALSE;
                    alarm( 0 );
/* write a message to system log */
                    sprintf( msg, "Ganglia gmond module netif: Disabling Ethernet adapter %s.",
                                  netif_devices[Signal_devIndex].devName );
                    syslog( LOG_WARNING, msg );
                    longjmp( my_jumpbuf, 1 );
                    break;

   }
}
#endif



static time_t
boottime_func_CALLED_ONCE( void )
{
   time_t  boottime;
   g_val_t val;


   val = boottime_func();

   boottime = val.uint32;

   return( boottime );
}



static int
detect_and_verify_netif_devices( void )
{
   char *p,
        *src;
   int count;


/* find out the number of available Ethernet devices */

   count = 0;

   p = update_file( &proc_net_dev );


/* skip past the two-line header ... */
   p = index( p, '\n' ) + 1;
   p = index( p, '\n' ) + 1;

   while (*p != '\0' )
   {
      while ((p != '\0') && isblank(*p))
         p++;

      src = p;

      p = index( p, ':' );

      if (p)
      {
         count++; 

/* ignore the rest if the line for now */
         p = index( p, '\n' ) + 1;
      }
   }

#ifdef DEBUG
fprintf( stderr, "Found Ethernet adapters = %d\n", count );  fflush( stderr );
#endif

   if (count == 0)
      return( 0 );


/* allocate the proper data structures */
   netif_devices = malloc( count * sizeof( netif_devices_t ) );
   if (! netif_devices)
      return( -1 );


/* reset the counter */
   count = 0;


/* now read the device name strings */
   p = update_file( &proc_net_dev );

/* skip past the two-line header ... */
   p = index( p, '\n' ) + 1;
   p = index( p, '\n' ) + 1;

   while (*p != '\0')
   {
      while ((*p != '\0') && isblank( *p ))
         p++;

      src = p;

      p = index( p, ':' );

      if (p)
      {
         netif_devices[count].enabled = TRUE;
         netif_devices[count].threshold = MIN_THRESHOLD;

         strncpy( netif_devices[count].devName, src, p - src );
         netif_devices[count].devName[p - src] = '\0';
         p++;

         count++; 

/* ignore the rest if the line for now */
         p = index( p, '\n' ) + 1;
      }
   }

#ifdef DEBUG
{
int i;
for (i = 0;  i < count;  i++)
   fprintf( stderr, "name = >%s<\n", netif_devices[i].devName );
fflush( stderr );
}
#endif


/* return the number of found Ethernet devices */
   return( count );
}



static void
read_device( int devIndex, double delta_t, double now )
{
   char *p;
   int i;
   long long bytes_received,
             bytes_sent,
             pkts_received,
             pkts_sent,
             delta;


#ifdef USE_SIGNALS
/* for the signal handler, remember the current questioned device */
   Signal_devIndex = devIndex;

   if( setjmp( my_jumpbuf ) != 0)
      return;

   signal( SIGALRM, my_sig_handler );
   alarm( 5 );   /* allow a maximum of 5 seconds for running the entstat command */
#endif

   bytes_received = bytes_sent = pkts_received = pkts_sent = -1LL;

/* now read the device values */
   p = update_file( &proc_net_dev );

/* skip past the two-line header ... */
   p = index( p, '\n' ) + 1;
   p = index( p, '\n' ) + 1;

/* look for the occurence of the device name */
   p = strstr( p, netif_devices[devIndex].devName );

/* find the colon terminating the device name */
   while ((*p != '\0') && (*p != ':'))
      p++;

   p++;

/* skip blanks until we read the first data element */
   while ((*p != '\0') && isblank( *p ))
      p++;

/* bytes received */
   bytes_received = strtoll( p, &p, 10 );
  
/* pkts received */
   pkts_received = strtoll( p, &p, 10 );
 
/* skip unneeded metrics */
   for (i = 0;  i < 6;  i++)
     bytes_sent = strtoll( p, &p, 10 );

/* bytes sent */
   bytes_sent = strtoll( p, &p, 10 );
  
/* pkts sent */
   pkts_sent = strtoll( p, &p, 10 );
 
#ifdef USE_SIGNALS
   alarm( 0 );   /* disable the timeout again */
#endif

#ifdef DEBUG
fprintf( stderr, "\n" );
fprintf( stderr, "now = %f, last_read = %f, delta_t = %f\n",
                 now,
                 netif_devices[devIndex].last_read,
                 delta_t );
fflush( stderr );
#endif

   if (bytes_received != -1LL)
   {
      delta = bytes_received - netif_bytes_received[devIndex].last_total_value;

#ifdef DEBUG
fprintf( stderr, "============== bytes_received( %s ) ========================\n", 
                 netif_devices[devIndex].devName );
fprintf( stderr, "read_val = %lld, last_val = %lld, delta = %lld\n",
                 bytes_received,
                 netif_bytes_received[devIndex].last_total_value,
                 delta );
#endif

      if (delta < 0)
      {
         netif_bytes_received[devIndex].curr_value = netif_bytes_received[devIndex].last_value;
      }
      else
      {
         netif_bytes_received[devIndex].curr_value = (double) delta / delta_t;
      }
      
      netif_bytes_received[devIndex].last_value = netif_bytes_received[devIndex].curr_value;
      netif_bytes_received[devIndex].last_total_value = bytes_received;
   }

   if (bytes_sent != -1LL)
   {
      delta = bytes_sent - netif_bytes_sent[devIndex].last_total_value;

#ifdef DEBUG
fprintf( stderr, "============== bytes_sent ( %s ) ========================\n", 
                 netif_devices[devIndex].devName );
fprintf( stderr, "read_val = %lld, last_val = %lld, delta = %lld\n",
                 bytes_sent,
                 netif_bytes_sent[devIndex].last_total_value,
                 delta );
#endif

      if (delta < 0)
      {
         netif_bytes_sent[devIndex].curr_value = netif_bytes_sent[devIndex].last_value;
      }
      else
      {
         netif_bytes_sent[devIndex].curr_value = (double) delta / delta_t;
      }
      
      netif_bytes_sent[devIndex].last_value = netif_bytes_sent[devIndex].curr_value;
      netif_bytes_sent[devIndex].last_total_value = bytes_sent;
   }

   if (pkts_received != -1LL)
   {
      delta = pkts_received - netif_pkts_received[devIndex].last_total_value;

#ifdef DEBUG
fprintf( stderr, "============== pkts_received ( %s ) ========================\n", 
                 netif_devices[devIndex].devName );
fprintf( stderr, "read_val = %lld, last_val = %lld, delta = %lld\n",
                 pkts_received,
                 netif_pkts_received[devIndex].last_total_value,
                 delta );
#endif

      if (delta < 0)
      {
         netif_pkts_received[devIndex].curr_value = netif_pkts_received[devIndex].last_value;
      }
      else
      {
         netif_pkts_received[devIndex].curr_value = (double) delta / delta_t;
      }
      
      netif_pkts_received[devIndex].last_value = netif_pkts_received[devIndex].curr_value;
      netif_pkts_received[devIndex].last_total_value = pkts_received;
   }

   if (pkts_sent != -1LL)
   {
      delta = pkts_sent - netif_pkts_sent[devIndex].last_total_value;

#ifdef DEBUG
fprintf( stderr, "============== pkts_sent ( %s ) ========================\n", 
                 netif_devices[devIndex].devName );
fprintf( stderr, "read_val = %lld, last_val = %lld, delta = %lld\n",
                 pkts_sent,
                 netif_pkts_sent[devIndex].last_total_value,
                 delta );
#endif

      if (delta < 0)
      {
         netif_pkts_sent[devIndex].curr_value = netif_pkts_sent[devIndex].last_value;
      }
      else
      {
         netif_pkts_sent[devIndex].curr_value = (double) delta / delta_t;
      }
      
      netif_pkts_sent[devIndex].last_value = netif_pkts_sent[devIndex].curr_value;
      netif_pkts_sent[devIndex].last_total_value = pkts_sent;
   }

#ifdef DEBUG
fprintf( stderr, "\n" );
fflush( stderr );
#endif

   netif_devices[devIndex].last_read = now;
}



static double
get_current_time( void )
{
   struct timeval timeValue;
   struct timezone timeZone;


   gettimeofday( &timeValue, &timeZone );

   return( (double) (timeValue.tv_sec - boottime) + (timeValue.tv_usec / 1000000.0) );
}



static double
time_diff( int netif_index, double *now )
{
   *now = get_current_time();

   return( *now - netif_devices[netif_index].last_read );
}



static g_val_t
netif_bytes_received_func( int netif_index )
{
   double delta_t,
          now;
   g_val_t val;


   if (netif_devices[netif_index].enabled)
   {
      delta_t = time_diff( netif_index, &now );

      if (delta_t > netif_devices[netif_index].threshold)
         read_device( netif_index, delta_t, now );

      val.d = netif_bytes_received[netif_index].curr_value;
   }
   else
      val.d = -1.0;

#ifdef DEBUG
fprintf( stderr, "netif_bytes_received_func = %f\n", val.d ); fflush( stderr );
#endif


   return( val );
}



static g_val_t
netif_bytes_sent_func( int netif_index )
{
   double delta_t,
          now;
   g_val_t val;


   if (netif_devices[netif_index].enabled)
   {
      delta_t = time_diff( netif_index, &now );

      if (delta_t > netif_devices[netif_index].threshold)
         read_device( netif_index, delta_t, now );

      val.d = netif_bytes_sent[netif_index].curr_value;
   }
   else
      val.d = -1.0;

#ifdef DEBUG
fprintf( stderr, "netif_bytes_sent_func = %f\n", val.d ); fflush( stderr );
#endif


   return( val );
}



static g_val_t
netif_pkts_received_func( int netif_index )
{
   double delta_t,
          now;
   g_val_t val;


   if (netif_devices[netif_index].enabled)
   {
      delta_t = time_diff( netif_index, &now );

      if (delta_t > netif_devices[netif_index].threshold)
         read_device( netif_index, delta_t, now );

      val.d = netif_pkts_received[netif_index].curr_value;
   }
   else
      val.d = -1.0;

#ifdef DEBUG
fprintf( stderr, "netif_pkts_received_func = %f\n", val.d ); fflush( stderr );
#endif


   return( val );
}



static g_val_t
netif_pkts_sent_func( int netif_index )
{
   double delta_t,
          now;
   g_val_t val;


   if (netif_devices[netif_index].enabled)
   {
      delta_t = time_diff( netif_index, &now );

      if (delta_t > netif_devices[netif_index].threshold)
         read_device( netif_index, delta_t, now );

      val.d = netif_pkts_sent[netif_index].curr_value;
   }
   else
      val.d = -1.0;

#ifdef DEBUG
fprintf( stderr, "netif_pkts_sent_func = %f\n", val.d ); fflush( stderr );
#endif


   return( val );
}



/* Initialize the given metric by allocating the per metric data
   structure and inserting a metric definition for each network
   interface found.
*/
static net_perf_data_t *init_metric( apr_pool_t *p,
                                     apr_array_header_t *ar,
                                     int netif_count,
                                     char *name,
                                     char *desc,
                                     char *units )
{
   int i;
   Ganglia_25metric *gmi;
   net_perf_data_t *netif;


   netif = apr_pcalloc( p, sizeof( net_perf_data_t ) * netif_count );

   for (i = 0;  i < netif_count;  i++)
   {
      gmi = apr_array_push( ar );

      /* gmi->key will be automatically assigned by gmond */
      gmi->name = apr_psprintf( p, "%s_%s", netif_devices[i].devName, name );
      gmi->tmax = 60;
      gmi->type = GANGLIA_VALUE_DOUBLE;
      gmi->units = apr_pstrdup( p, units );
      gmi->slope = apr_pstrdup( p, "both" );
      gmi->fmt = apr_pstrdup( p, "%.1f" );
      gmi->msg_size = UDP_HEADER_SIZE + 16;
      gmi->desc = apr_psprintf( p, "%s %s", netif_devices[i].devName, desc );
   }

   return( netif );
}



/*
 * Declare ourselves so the configuration routines can find and know us.
 * We'll fill it in at the end of the module.
 */
extern mmodule netif_module;


static int netif_metric_init ( apr_pool_t *p )
{
   int i;
   double now;
   Ganglia_25metric *gmi;


/* Initialize all required data and structures */

   netif_count = detect_and_verify_netif_devices();


/* Allocate a pool that will be used by this module */
   apr_pool_create( &pool, p );

   metric_info = apr_array_make( pool, 2, sizeof( Ganglia_25metric ) );


/* Initialize each metric */
   netif_bytes_received = init_metric( pool,
                                       metric_info,
                                       netif_count,
                                       "bytes_received",
                                       "Bytes Received",
                                       "bytes/sec" );
   netif_bytes_sent = init_metric( pool,
                                   metric_info,
                                   netif_count,
                                   "bytes_sent",
                                   "Bytes Sent",
                                   "bytes/sec" );
   netif_pkts_received = init_metric( pool,
                                      metric_info,
                                      netif_count,
                                      "pkts_received",
                                      "Packets Received",
                                      "packets/sec" );
   netif_pkts_sent = init_metric( pool,
                                  metric_info,
                                  netif_count,
                                  "pkts_sent",
                                  "Packets Sent",
                                  "packets/sec" );


/* Add a terminator to the array and replace the empty static metric definition
   array with the dynamic array that we just created
*/
   gmi = apr_array_push( metric_info );
   memset( gmi, 0, sizeof( *gmi ));

   netif_module.metrics_info = (Ganglia_25metric *) metric_info->elts;


   for (i = 0;  netif_module.metrics_info[i].name != NULL;  i++)
   {
      /* Initialize the metadata storage for each of the metrics and then
       *  store one or more key/value pairs.  The define MGROUPS defines
       *  the key for the grouping attribute. */
      MMETRIC_INIT_METADATA( &(netif_module.metrics_info[i]), p );
      MMETRIC_ADD_METADATA( &(netif_module.metrics_info[i]), MGROUP, "netif" );
   }


/* initialize the routines which require a time interval */

   boottime = boottime_func_CALLED_ONCE();
   now = get_current_time();
   for (i = 0;  i < netif_count;  i++)
   {
      read_device( i, 1.0, now );

      netif_bytes_received[i].curr_value = 0.0;
      netif_bytes_sent[i].curr_value = 0.0;
      netif_pkts_received[i].curr_value = 0.0;
      netif_pkts_sent[i].curr_value = 0.0;
   }


/* return OK */
   return( 0 );
}



static void netif_metric_cleanup ( void )
{
}



static g_val_t netif_metric_handler ( int metric_index )
{
   g_val_t val;
   char *p,
         name[256];
   int i, devIndex; 


/* Get the metric name and device index from the combined name that was
 * passed in
 */
   strcpy( name, netif_module.metrics_info[metric_index].name );

   p = index( name, '_' ) + 1;
   name[p - name - 1] = '\0';


/* now we need to match the name with the name of all found Ethernet devices */
   devIndex = -1;

   for (i = 0;  i < netif_count;  i++)
     if (strcmp( name, netif_devices[i].devName ) == 0)
     {
        devIndex = i;
        break;
     }

   if (devIndex == -1)
   {
      val.uint32 = 0; /* default fallback */
      return( val );
   }


/* jump into the right function */

   if (strcmp( p, "bytes_received" ) == 0)
      return( netif_bytes_received_func( devIndex ) );

   if (strcmp( p, "bytes_sent" ) == 0)
      return( netif_bytes_sent_func( devIndex ) );

   if (strcmp( p, "pkts_received" ) == 0)
      return( netif_pkts_received_func( devIndex ) );

   if (strcmp( p, "pkts_sent" ) == 0)
      return( netif_pkts_sent_func( devIndex ) );

   val.uint32 = 0; /* default fallback */
   return( val );
}



mmodule netif_module =
{
   STD_MMODULE_STUFF,
   netif_metric_init,
   netif_metric_cleanup,
   NULL, /* defined dynamically */
   netif_metric_handler
};



#ifndef STANDALONE_DEBUG
/* compile with:
gcc -DHAVE_CONFIG_H -I. -I../../.. -I/usr/include/apr-1    -I../../../include -I../../../lib -I../../../libmetrics mod_netif.c -L../../../libmetrics/.libs/ -lmetrics -L../../../libmetrics/linux/.libs -lmetric25 -L../../../lib/.libs -lganglia
*/

int main( int argc, char *argv[] )
{
   int i,
       count;


   count = detect_and_verify_netif_devices();

   netif_bytes_received = calloc( sizeof( net_perf_data_t ), count );
   netif_pkts_received = calloc( sizeof( net_perf_data_t ), count );
   netif_bytes_sent = calloc( sizeof( net_perf_data_t ), count );
   netif_pkts_sent = calloc( sizeof( net_perf_data_t ), count );

   for (i = 0;  i < count;  i++)
      read_device( i, 1.0, get_current_time() );

   sleep( 2 );

   for (i = 0;  i < count;  i++)
      read_device( i, 2.0, get_current_time() );

   sleep( 2 );

   for (i = 0;  i < count;  i++)
      read_device( i, 2.0, get_current_time() );

   return( 0 );
}
#endif

