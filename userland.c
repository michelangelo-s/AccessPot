#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

//The multicast group that we
//broadcast messages to on userland
#define NETLINK_GROUP 21
//the path in which the logs will be saved
#define PATH_TO_LOG_FILE "/var/log/accesspot.log"
//the maximum amount of data expecting the kernel
//to give us (it's in sync with the max buf size of the kernel)
#define CHUNK_SIZE 4096

char* get_current_timestamp(void)
{ 
        //initialize our variables
        time_t now;
        char* timestamp;
        unsigned int temp, year, second, minute, hour;

        //Allocate some more-than-enough space
        //for our timestamp
        timestamp = (char*)malloc(4096);
        //get the amount of seconds 
        //passed since epoch
        now = time(NULL);

        //calculate all fields needed
        temp = now;
        year = (1970 + (temp / 31556952));
        second = temp%60;
        temp /= 60;
        minute = temp%60;
        temp /= 60;
        hour = temp%24;

        //format everything into one string, and save it to our buffer
        sprintf(timestamp, "GMT0 %d %02d:%02d:%02d", year, hour, minute, second);

        //return the pointer of the
        //timestamp string
        return timestamp;
}

void append_to_file(char* fileName, char* content)
{
    //initialize our variables
    ssize_t messageLength;
    int fd;

    //get the length of the content to write
    messageLength = strlen(content);

    //open the file with write, append and creation (if not exists)
    //along with the permissions to read and write for the user only
    fd = open(fileName, O_WRONLY | O_APPEND | O_CREAT, 600);
    //write the content to the file
    write(fd, content, messageLength);
    //close the file handle
    close(fd);
}

int open_netlink_connection(void)
{
    //initialize our variables
    int sock;
    struct sockaddr_nl addr;
    int group = NETLINK_GROUP;

    //open a new socket connection
    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);

    //if the socket failed to open,
    if (sock < 0) 
    {
        //inform the user
        printf("Socket failed to initialize.\n");
        //return the error value
        return sock;
    }

    //initialize our addr structure by filling it with zeros
    memset((void *) &addr, 0, sizeof(addr));
    //specify the protocol family
    addr.nl_family = AF_NETLINK;
    //set the process id to the current process id
    addr.nl_pid = getpid();

    //bind the address to the socket created, and if it failed,
    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) 
    {
        //inform the user
        printf("bind < 0.\n");
        //return the function with a symbolic error code
        return -1;
    }

    //set the option so that we can receive packets whose destination
    //is the group address specified (so that we can receive the message broadcasted by the kernel)
    if (setsockopt(sock, 270, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) 
    {
        //if it failed, inform the user
        printf("setsockopt < 0\n");
        //return the function with a symbolic error code
        return -1;
    }

    //if we got thus far, then everything
    //went fine. Return our socket.
    return sock;
}

char* read_kernel_message(int sock)
{
    //initialize the variables
    //that we are going to need
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;
    char* buffer[CHUNK_SIZE];
    char* kernelMessage;
    int ret;

    //specify the buffer to save the message
    iov.iov_base = (void *) &buffer;
    //specify the length of our buffer
    iov.iov_len = sizeof(buffer);

    //pass the pointer of our sockaddr structure
    //that will save the source IP and port of the connection
    msg.msg_name = (void *) &(nladdr);
    //give the size of our structure
    msg.msg_namelen = sizeof(nladdr);
    //pass our scatter/gather I/O structure pointer
    msg.msg_iov = &iov;
    //we will pass only one buffer array,
    //therefore we will specify that here
    msg.msg_iovlen = 1;

    //listen/wait for new data
    ret = recvmsg(sock, &msg, 0);

    //if message was received successfully,
    if(ret >= 0)
    {
        //get the string data and save them to a local variable
        char* buf = NLMSG_DATA((struct nlmsghdr *) &buffer);

        //allocate memory for our kernel message
        kernelMessage = (char*)malloc(CHUNK_SIZE);

        //copy the kernel data to our allocated space
        strcpy(kernelMessage, buf);

        //return the pointer that points to the kernel data
        return kernelMessage;
    }
    
    //if we got that far, reading the message failed,
    //so we inform the user and return a NULL pointer
    printf("Message could not received.\n");
    return NULL;
}

int main(int argc, char *argv[])
{
    //initialize our variables
    int netlinkSocket;
    char finalMessage[CHUNK_SIZE + 1024]; //+1024 just to be safe for the timestamp

    //if the current user is NOT root,
    //that means that he doesn't have enough requirements
    //to do the netlink connection
    if(getuid() != 0)
    {
        //inform the user
        printf("This program needs to be run as root!\n");
        //return the function with symbolic error code
        return 1;
    }

    //open the bind netlink connection
    netlinkSocket = open_netlink_connection();

    //if the netlink connection failed,
    if (netlinkSocket < 0)
    {
        //inform the user
        printf("Failed to open netlink connection!");
        //return the error message given
        return netlinkSocket;
    }

    //inform the user that the bind connection was made successfully
    printf("Netlink connection established!\n");

    //Make the R/W log procedure
    //running until the user forcefully
    //closes the program
    while (1)
    {
        //initialize the whole array with zeros
        memset(finalMessage, 0, sizeof(finalMessage));

        //get the log from kernel (blocking I/O)
        char* buffer = read_kernel_message(netlinkSocket);

        //print the log to the console (for debugging purposes)
        printf("Received kernel message: %s\n", buffer);

        //concatenare the current time and date in the beginning
        //of the final message, and then add the actual kernel log
        strcat(finalMessage, get_current_timestamp());
        strcat(finalMessage, " - ");
        strcat(finalMessage, buffer);
        strcat(finalMessage, "\n");

        //append the final log string to the log file
        append_to_file(PATH_TO_LOG_FILE, finalMessage);

        //free the memory of the buffer
        free(buffer);
    }

    return 0;
}