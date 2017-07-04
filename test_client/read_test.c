#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
 
#define BUFFER_SIZE 256
#define DEV_NAME "/dev/cc_hooker"
static char rcv_msg[BUFFER_SIZE];
 
int main(){
    int ret, fd = 0;
    
    printf("Starting Cave-Canem client test\n");
    fd = open(DEV_NAME, O_RDWR);
    if (fd < 0){
        perror("Failed to open the device!");
        return errno;
    }
    printf("Listening Cave Canem LKM...\nC.C. say:\n");
    
    while(ret >=0){
        ret = read(fd, rcv_msg, BUFFER_SIZE);
        if (strlen(rcv_msg)){
            printf("%s", rcv_msg);
            memset(&rcv_msg, 0, BUFFER_SIZE);
        }
        sleep(0.5);
    }
    perror("Failed to read the message from the device.\n");
    printf("BYE!\n");
    close(fd);
    return errno;
}
