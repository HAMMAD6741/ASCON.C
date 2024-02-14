#include "contiki.h"
#include "lib/random.h"
#include "sys/ctimer.h"
#include "net/uip.h"
#include "net/uip-ds6.h"
#include "net/uip-udp-packet.h"
#include "sys/ctimer.h"
#ifdef WITH_COMPOWER
#include "powertrace.h"
#endif /* \
        */
#include <stdio.h>
#include <string.h>

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

#define UDP_EXAMPLE_ID 190

#define DEBUG DEBUG_PRINT
#include "net/uip-debug.h"

#ifndef PERIOD
#define PERIOD 60
#endif /* \
        */

#define START_INTERVAL (15 * CLOCK_SECOND)
#define SEND_INTERVAL (PERIOD * CLOCK_SECOND)
#define SEND_TIME (random_rand() % (SEND_INTERVAL))
#define MAX_PAYLOAD_LEN 255

static struct uip_udp_conn *client_conn;

static uip_ipaddr_t server_ipaddr;

/* ASCON CODE */
typedef uint64_t bit64;

bit64 constants[16] =
    {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x69, 0x5a, 0x4b, 0x3c,
     0x2d, 0x1e, 0x0f};

bit64 state[5] = {0}, t[5] = {0};

bit64 rotate(bit64 x, int l)
{

    bit64 temp;

    temp = (x >> l) ^ (x << (64 - l));

    return temp;
}

void print_state(bit64 state[5])
{

    printf(" key[0] :%016llxx\n", state[1]);

    printf(" IV :%016llxx\n", state[0]);

    printf(" key[1] :%016llxx\n", state[2]);

    printf(" nonce[0] :%016llxx\n", state[3]);

    printf(" nonce[1] :%016llxx\n", state[4]);
}
void

sbox(bit64 x[5])
{

    x[0] ^= x[4];
    x[4] ^= x[3];
    x[2] ^= x[1];

    t[0] = x[0];
    t[1] = x[1];
    t[2] = x[2];
    t[3] = x[3];
    t[4] = x[4];

    t[0] = ~t[0];
    t[1] = ~t[1];
    t[2] = ~t[2];
    t[3] = ~t[3];
    t[4] = ~t[4];

    t[0] &= x[1];
    t[1] &= x[2];
    t[2] &= x[3];
    t[3] &= x[4];
    t[4] &= x[0];

    x[0] ^= t[1];
    x[1] ^= t[2];
    x[2] ^= t[3];
    x[3] ^= t[4];
    x[4] ^= t[0];

    x[1] ^= x[0];
    x[0] ^= x[4];
    x[3] ^= x[2];
    x[2] = ~x[2];
}

void

linear(bit64 state[5])
{

    bit64 temp0, temp1;

    temp0 = rotate(state[0], 19);

    temp1 = rotate(state[0], 28);

    state[0] ^= temp0 ^ temp1;

    temp0 = rotate(state[1], 61);

    temp1 = rotate(state[1], 39);

    state[1] ^= temp0 ^ temp1;

    temp0 = rotate(state[2], 1);

    temp1 = rotate(state[2], 6);

    state[2] ^= temp0 ^ temp1;

    temp0 = rotate(state[3], 10);

    temp1 = rotate(state[3], 17);

    state[3] ^= temp0 ^ temp1;

    temp0 = rotate(state[4], 7);

    temp1 = rotate(state[4], 41);

    state[4] ^= temp0 ^ temp1;
}

void

add_constant(bit64 state[5], int i, int a)
{

    state[2] = state[2] ^ constants[12 - a + i];
}

void

p(bit64 state[5], int a)
{

    int i;

    for (i = 0; i < a; i++)
    {

        add_constant(state, i, a);

        sbox(state);

        linear(state);
    }
}

void initialization(bit64 state[5], bit64 key[2])
{

    p(state, 12);

    state[3] ^= key[0];

    state[4] ^= key[1];
}
void

encrypt(bit64 state[5], int lenght, bit64 plaintext[], bit64 ciphertext[])
{

    ciphertext[0] = plaintext[0] ^ state[0];

    int i;

    for (i = 1; i < lenght; i++)
    {

        p(state, 6);

        ciphertext[i] = plaintext[i] ^ state[0];

        state[0] = plaintext[i] ^ state[0];
    }
}

void finalization(bit64 state[5], bit64 key[2])
{

    state[0] ^= key[0];

    state[1] ^= key[1];

    p(state, 12);
}

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client process");

AUTOSTART_PROCESSES(&udp_client_process);

/*---------------------------------------------------------------------------*/
static void
tcpip_handler(void)
{
    char *str;

    if (uip_newdata())
    {

        str = uip_appdata;

        str[uip_datalen()] = '\0';

        printf("DATA recv '%s'\n", str);
    }
}

/*---------------------------------------------------------------------------*/
static void
send_packet(void *ptr)
{

    bit64 nonce[2] = {0};

    bit64 key[2] = {0};

    bit64 IV = 0x80400c8600000000;

    bit64 plaintext[] = {0x123456789abcdef, 0x82187}, ciphertext[10] = {0};

    state[0] = IV;

    state[1] = key[0];

    state[2] = key[1];

    state[3] = nonce[0];

    state[4] = nonce[1];

    initialization(state, key);

    print_state(state);

    encrypt(state, 2, plaintext, ciphertext);

    // printf("ciphertext: %016llxx %016llxx\n", ciphertext[0], ciphertext[1]);

    finalization(state, key);

    // printf();

    // printf("Ascon Code Compiled\n");

    static int seq_id;

    char buf[MAX_PAYLOAD_LEN];

    seq_id++;

//   Local Message
    PRINTF("DATA send to %d 'Message Sequence: %d'\n",server_ipaddr.u8[sizeof(server_ipaddr.u8) - 1], seq_id);
//  Actual Message Sent
    sprintf(buf , "ciphertext: %016llxx %016llxx tag: %016llxx %016llxx Message Sequence: %d\n", ciphertext[0], ciphertext[1], state[3], state[4], seq_id);

    uip_udp_packet_sendto(client_conn, buf, strlen(buf),  &server_ipaddr,
                          UIP_HTONS(UDP_SERVER_PORT));
}

/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
    int i;

    uint8_t state;

    PRINTF("Client IPv6 addresses: ");

    for (i = 0; i < UIP_DS6_ADDR_NB; i++)
    {

        state = uip_ds6_if.addr_list[i].state;

        if (uip_ds6_if.addr_list[i].isused &&
            (state == ADDR_TENTATIVE || state == ADDR_PREFERRED))
        {

            PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);

            PRINTF("\n");

            /* hack to make address "final" */
            if (state == ADDR_TENTATIVE)
            {

                uip_ds6_if.addr_list[i].state = ADDR_PREFERRED;
            }
        }
    }
}

/*---------------------------------------------------------------------------*/
static void
set_global_address(void)
{
    uip_ipaddr_t ipaddr;

    uip_ip6addr(&ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 0);

    uip_ds6_set_addr_iid(&ipaddr, &uip_lladdr);

    uip_ds6_addr_add(&ipaddr, 0, ADDR_AUTOCONF);

    /* The choice of server address determines its 6LoPAN header compression.
     * (Our address will be compressed Mode 3 since it is derived from our link-local address)
     * Obviously the choice made here must also be selected in udp-server.c.
     *
     * For correct Wireshark decoding using a sniffer, add the /64 prefix to the 6LowPAN protocol preferences,
     * e.g. set Context 0 to aaaa::.  At present Wireshark copies Context/128 and then overwrites it.
     * (Setting Context 0 to aaaa::1111:2222:3333:4444 will report a 16 bit compressed address of aaaa::1111:22ff:fe33:xxxx)
     *
     * Note the IPCMV6 checksum verification depends on the correct uncompressed addresses.
     */

#if 0
/* Mode 1 - 64 bits inline */ 
    uip_ip6addr (&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0, 0, 1);

#elif 1
    /* Mode 2 - 16 bits inline */
    uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0, 0x00ff, 0xfe00, 1);

#else  /* \
        */
    /* Mode 3 - derived from server link-local (MAC) address */
    uip_ip6addr(&server_ipaddr, 0xaaaa, 0, 0, 0, 0x0250, 0xc2ff, 0xfea8, 0xcd1a); // redbee-econotag
#endif /* \
        */
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
    static struct etimer periodic;

    static struct ctimer backoff_timer;

#if WITH_COMPOWER
    static int print = 0;

#endif /* \
        */

    PROCESS_BEGIN();

    PROCESS_PAUSE();

    set_global_address();

    PRINTF("UDP client process started\n");

    print_local_addresses();

    /* new connection with remote host */
    client_conn = udp_new(NULL, UIP_HTONS(UDP_SERVER_PORT), NULL);

    if (client_conn == NULL)
    {

        PRINTF("No UDP connection available, exiting the process!\n");

        PROCESS_EXIT();
    }

    udp_bind(client_conn, UIP_HTONS(UDP_CLIENT_PORT));

    PRINTF("Created a connection with the server ");

    PRINT6ADDR(&client_conn->ripaddr);

    PRINTF(" local/remote port %u/%u\n",
           UIP_HTONS(client_conn->lport),
           UIP_HTONS(client_conn->rport));

#if WITH_COMPOWER
    powertrace_sniff(POWERTRACE_ON);

#endif /* \
        */

    etimer_set(&periodic, SEND_INTERVAL);

    while (1)
    {

        PROCESS_YIELD();

        if (ev == tcpip_event)
        {

            tcpip_handler();
        }

        if (etimer_expired(&periodic))
        {

            etimer_reset(&periodic);

            ctimer_set(&backoff_timer, SEND_TIME, send_packet, NULL);

#if WITH_COMPOWER
            if (print == 0)
            {

                powertrace_print("#P");
            }

            if (++print == 3)
            {

                print = 0;
            }

#endif /* \
        */
        }
    }

    PROCESS_END();
}

/*---------------------------------------------------------------------------*/
