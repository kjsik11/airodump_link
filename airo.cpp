#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <list>


int count;
void airodump(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
struct link_list{
    struct beacons *head;
    struct beacons *search;
};


typedef struct beacons{
    int PWD;
    int beacons;
    int bssid[6];
    char essid[30];
    u_int8_t ssid_len;
    struct beacons *next;
}beacon;

struct link_list *temp;

int main(int argc, char *argv[])
{
  //  temp->head=NULL;
    //temp->search=NULL;




    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    printf("%s\n",dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    }
    u_char *arg =NULL;
    pcap_loop(handle,0,pcap_handler(airodump),arg);


    pcap_close(handle);
        return(2);

}



int cmp_bssid(struct link_list *L,int temp[]){
    int s1=0;
    L->search=L->head;
    while(L->search!=NULL){
        for(int i=0;i<6;i++){
            if(L->head->bssid[i]==temp[i])
                    s1++;
        }
        if(s1==6) return 1;

        L->search=L->search->next;
    }
    return 2;
}

void add_bssid(struct link_list *L,beacon *B){
    L->search=L->head;
    if(L->search==NULL){
        L->head=B;
        return;
    }
    while(L->search!=NULL){
        L->search=L->search->next;
        if(L->search==NULL)
            L->search->next=B;
    }
}

void print_beacon(struct link_list *L){
    L->search=L->head;
    printf("BSSID                   Beacons  PWD(notdBm)      ESSID\n");
    printf("======================================================\n");
    while(L->search!=NULL){
        for(int k=0;k<6;k++){
            printf("%2x",L->search->bssid[k]);
            if(k<5)
                printf(":");
        }



        printf("%10d",L->search->beacons);
        printf("%10d",L->search->PWD);
        printf("\t\t");
        for(int k=0;k<L->search->ssid_len;k++){
            printf("%c",L->search->essid[k]);
        }
        L->search=L->search->next;
    }
}

void airodump(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

    struct link_list *L=(link_list*)malloc(sizeof(link_list));
    L->head=NULL;
    L->search=NULL;;

    int temp_bssid[6];
    for(int k=0;k<6;k++){
        temp_bssid[k]=*(pkt_data+40+k);
    }

    int a = cmp_bssid(L,temp_bssid);
    if(a==1) L->search->beacons++;
    else{
        beacon *newbeacon = (beacon *)malloc(sizeof(beacon));

        newbeacon->next = NULL;
        newbeacon->PWD = *(pkt_data+18);
        newbeacon->beacons=0;
        for(int k=0;k<6;k++){
            newbeacon->bssid[k] = temp_bssid[k];
        }


        newbeacon->ssid_len = *(pkt_data+61);
        for(int k=0;k<newbeacon->ssid_len;k++){
            newbeacon->essid[k]=*(pkt_data+62+k);
        }

        add_bssid(L,newbeacon);
    }
        system ("clear");
        print_beacon(L);

        free(L);
        printf("\n");

}

/*
    for (i=0; i < header->len; i++) {
        if (i%16 == 0)
            printf("%p  ", ((unsigned char *)pkt_data + i));
        printf("%02x ", ((unsigned char *)pkt_data)[i]);
        if (i%16-15 == 0) {
            int j;
            printf("  ");
            for (j=i-15; j <= i; j++)
                printchar(((unsigned char *)pkt_data)[j]);
            printf("\n");
            }
        }
     if (i%16 != 0) {
        int j;
        int spaces = (header->len-i+16-i%16)*3+2;
        for (j=0; j < spaces; j++)
                printf(" ");
        for (j=i-i%16; j < header->len; j++)
            printchar(((unsigned char *)pkt_data)[j]);
        }
     printf("\n");
*/

