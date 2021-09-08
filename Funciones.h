int n; int cont=0,primerBytetrama,tamanioMAC =6, tamanioProtocolo,segundoBytetrama,socketRaw, tramasTotales =0, aux =0;
char auxDirMACs[2048], *source = "Origen",*destiny = "Destino",*trama = "Trama",*charge = "Carga";
unsigned char buffer[2048];
pthread_t thread1, thread2;
pthread_attr_t thread_att;
FILE *Archivo, *archivoAux;
struct ethhdr *cabeceraEthernet; 
unsigned char *data;
int longitudDatos, protocol,tramasEthernet =0,  conteoIEEE=0, conteoOtras = 0,conteoIPv4 =0, conteoIPv6 = 0, conteoARP =0;
char array_addr[12];

struct address
{
    char direccionMAC[17];
    int cont;
};
struct addresses
{
    struct address macAddress;
    struct addresses *siguienteDireccion;      
};

/* Estructuras para hilos de captura y análisis de trama*/
struct frame_capturador
{
    int sock;
    unsigned char *trama;
    struct sockaddr *tramaAux;
    socklen_t *longitudTrama;
};

struct frame_analizador{    
    unsigned char *trama;
    int tramaAnalizada;
};

struct addresses *Primero = NULL;

// Método para capturar las tramas
void *frame_captura(void *arg){
    struct frame_capturador *auxTrama;
    auxTrama =  (struct frame_capturador *)arg;
    n = recvfrom(auxTrama->sock, auxTrama->trama, 2048, 0, (struct sockaddr*)&auxTrama->tramaAux, (socklen_t*)&auxTrama->longitudTrama);
    pthread_exit(0);
}

void imprimirTramas(struct frame_analizador *tramas,FILE *archivo,char *packet){
    unsigned char *piv_frame =  tramas->trama;
            int sizeFrame = tramas->tramaAnalizada;
            fprintf(archivo, "%s:\n",packet);

            while(sizeFrame){
                fprintf(archivo, "%.2X ", *piv_frame);
                piv_frame++;
                sizeFrame--;
            }
            fprintf(archivo, "\n");
}

void typeMAC(unsigned char *Tramas,FILE *archivo, char *whereCome, int size){
    cont = 0;
    fprintf(Archivo, "Direccion MAC %s: ",whereCome);
    while(cont<size){
        if((size-cont) == 1){
            fprintf(archivo, "%.2X ", *Tramas);
        }
        else{
            fprintf(archivo, "%.2X:", *Tramas);
        }                
        Tramas++;
        cont++;
    }
    unsigned char *auxComunicacion =  (void *)Tramas;
    primerBytetrama = *auxComunicacion;
    if(primerBytetrama%2 == 0){
        fprintf(archivo, "\tComunicacion MAC %s: Unidifusion",whereCome);
    }                
    else{
        fprintf(archivo, "Comunicacion MAC %s: Multidifusion",whereCome);                    
    }
    fprintf(archivo, "\n");
}

void countSourceMAC(unsigned char *adressMAC){
    unsigned char *auxImprimirMAC = adressMAC;
    cont = 0;
    while(cont<tamanioMAC){
        if((tamanioMAC-cont) == 1){
            fprintf(archivoAux, "%.2X ", *auxImprimirMAC);
        }
        else{
            fprintf(archivoAux, "%.2X:", *auxImprimirMAC);
        }                
        auxImprimirMAC++;
        cont++;
    }
}

void printProtocol(unsigned char *tipoProtocolo){
    unsigned char *auxProtocolo = (void *)tipoProtocolo;
    tamanioProtocolo=2;
    while(tamanioProtocolo){
        fprintf(Archivo, "%.2X", *auxProtocolo);
        auxProtocolo++;
        tamanioProtocolo--;
    }
    fprintf(Archivo, "\n");
}
            
/* Para guardar direcciones */
void nuevasDirecciones(struct address addressNode){
    struct addresses *nuevasDirecciones = malloc(sizeof(struct addresses));
    nuevasDirecciones->macAddress=addressNode;
    nuevasDirecciones->siguienteDireccion=Primero;
    Primero=nuevasDirecciones;
}

/* Para contar direcciones */
void countAddress(char addr[17]){
    struct addresses *direccionesAux=Primero;
    while(direccionesAux!=NULL)
    {
        if((strcasecmp(direccionesAux->macAddress.direccionMAC, addr))==0){
        direccionesAux->macAddress.cont++;
        return;
        }
        direccionesAux=direccionesAux->siguienteDireccion;
    }
    struct address direccionAux;
    strcpy(direccionAux.direccionMAC, addr);
    direccionAux.cont =1;
    nuevasDirecciones(direccionAux);
}

/* método análisis de trama */
void *frame_analisis(void *arg){   
    /* aux */
    struct frame_analizador *auxTrama2;
    auxTrama2 = (struct frame_analizador *)arg;
    
    if(auxTrama2->tramaAnalizada >sizeof(struct ethhdr))
    {
        cabeceraEthernet = (struct ethhdr * )auxTrama2->trama;
        unsigned char *piv_prot =  (void *)&cabeceraEthernet->h_proto;
        primerBytetrama = *piv_prot;
        piv_prot++;
        segundoBytetrama = *piv_prot;
        if(primerBytetrama >= 0x06){
            tramasEthernet++;
            fprintf(Archivo, "\nLongitud trama: %d", auxTrama2->tramaAnalizada);
            data = auxTrama2->trama + sizeof(struct ethhdr);
            longitudDatos = auxTrama2->tramaAnalizada - sizeof(struct ethhdr);

            if(longitudDatos != 0){
                fprintf(Archivo, "\tLongitud carga util: %d\t", longitudDatos);
            }
            else{
                fprintf(Archivo, "\tLongitud carga util: 0000\t");
            }

            /* Para verificar el tipo de protocolo */
            unsigned char *tipoProtocolo =  (void *)&cabeceraEthernet->h_proto;
            primerBytetrama = *tipoProtocolo;
            tipoProtocolo++;
            segundoBytetrama = *tipoProtocolo;

            if((primerBytetrama==0x08) & (segundoBytetrama==0x00)){conteoIPv4++;}
            else if((primerBytetrama==0x86) & (segundoBytetrama==0xdd)){conteoIPv6++;}
            else if((primerBytetrama==0x08) & (segundoBytetrama==0x06)){conteoARP++;}

            /* Tipo de protocolo */
            fprintf(Archivo, "\tProtocolo: ");
            printProtocol((void *)&cabeceraEthernet->h_proto);

            typeMAC(cabeceraEthernet->h_source,Archivo,source,6);
            typeMAC(cabeceraEthernet->h_dest,Archivo,destiny,6);

            countSourceMAC(cabeceraEthernet->h_source);
            
            imprimirTramas(auxTrama2,Archivo,trama);
            imprimirTramas(auxTrama2,Archivo,charge);
        }
        else{
            //Para IEEE 802.3, no se analiza
            if((primerBytetrama<=0x05) & (segundoBytetrama<=0xdc))
            {        
                conteoIEEE++;
                fprintf(Archivo, "\n--Trama IEEE 802.3, no se analiza--\n");
                fprintf(Archivo, "Protocolo: ");
                printProtocol((void *)&cabeceraEthernet->h_proto);
            }
            else{
                conteoOtras++;
                fprintf(Archivo, "\n--Trama no identificada--\n");
            }
        }
    }
    else{
        fprintf(Archivo, "\n--Trama muy pequeña--\n");
    }
    pthread_exit(0);
}