#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <features.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "Funciones.h"
int main(int argc, char *argv[])
{   
    tramasTotales =0; aux =0;
    tramasTotales = atoi(argv[2]);
    struct sockaddr trama;
    int trama_length = sizeof(trama);
    struct frame_capturador fCap;
    struct frame_analizador fAna;
    Archivo = fopen("Sniffer.txt", "w+");
    archivoAux = fopen("SnifferA.txt", "w+");

    if(Archivo == NULL || archivoAux == NULL){
        fprintf(Archivo,"\nError al abrir archivos de texto\n");
        exit(1);
    }
    
    pthread_attr_init(&thread_att);
    pthread_attr_setdetachstate(&thread_att, PTHREAD_CREATE_JOINABLE);
    socketRaw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    if(socketRaw < 0){
        fprintf(Archivo,"\nError al crear socket\n");
        exit(1);
    }
    struct ifreq eth;
    bzero(&eth, sizeof(eth));
    strncpy((char *)eth.ifr_name, argv[1], IFNAMSIZ);
    ioctl(socketRaw, SIOCGIFFLAGS, &eth);
    // Modo promiscuo de la tarjeta de red
    eth.ifr_flags |= IFF_PROMISC;
    ioctl(socketRaw, SIOCGIFFLAGS, &eth);
    if(socketRaw < 0){
        fprintf(Archivo,"Error en bind del socket y tarjeta de red");
        exit(1);        
    }

    fprintf(Archivo, "Analizando entorno\n");
    for(int aux = 0; aux<tramasTotales; aux++){
        fprintf(Archivo, "\n*Analizando trama %d*\n", aux+1);

        // Se asignan valores de trama a la estructura de captura
        fCap.sock = socketRaw;
        fCap.trama = (unsigned char * )&buffer;
        fCap.tramaAux = (struct sockaddr*)&trama;
        fCap.longitudTrama = (socklen_t *)&trama_length;

        // Se crea hilo para capturar la trama
        pthread_create(&thread1, &thread_att, frame_captura, (void *)&fCap);
        pthread_join(thread1, NULL);
        if(n<0){
            fprintf(Archivo,"\nError al crear hilos\n");
            exit(1);
        }
        else{
            fAna.trama=(unsigned char *)&buffer;
            fAna.tramaAnalizada=n;
            /* Se crea hilo de análisis de trama */
            pthread_create(&thread2, &thread_att, frame_analisis, (void *)&fAna);
            pthread_join(thread2, NULL);
        }
    }
    fprintf(Archivo, "\nTABLA DE RESULTADOS\n");
    fprintf(Archivo, "\nEthernet II: %d", tramasEthernet);
    fprintf(Archivo, "\nIEEE 802.3: %d", conteoIEEE);
    fprintf(Archivo, "\nOtros: %d", conteoOtras);

    fprintf(Archivo, "\n__________________________________\n");
    fprintf(Archivo, "\nIPv4: %d", conteoIPv4);
    fprintf(Archivo, "\nIPv6: %d", conteoIPv6);
    fprintf(Archivo, "\nARP: %d", conteoARP);
    fprintf(Archivo, "\n__________________________________\n");

    fclose(archivoAux);

    /* Contador de direcciones */
    archivoAux = fopen("SnifferA.txt", "r");
    if(archivoAux == NULL){
        fprintf(Archivo,"\n--No fue posible recuperar direcciones--\n");
    }
    else{
        fprintf(Archivo, "\n--Direcciones MAC Origen--\n");
        while(feof(archivoAux) == 0){
            fgets(auxDirMACs, 2048, archivoAux);
        }
        char *separacionMACs = strtok(auxDirMACs," \n");
        while(separacionMACs != NULL){
            countAddress(separacionMACs);
            separacionMACs = strtok(NULL," \n");
        }
        struct addresses *imprimirMACs = Primero;
        while(imprimirMACs!=NULL){
            fprintf(Archivo, "%s -> Tramas asociadas: %d\n", 
            imprimirMACs->macAddress.direccionMAC, 
            imprimirMACs->macAddress.cont);
            imprimirMACs = imprimirMACs->siguienteDireccion;
        }
        fclose(Archivo);
        fclose(archivoAux);
        remove("SnifferA.txt");
        close(socketRaw);
    }            
    exit(0);
}