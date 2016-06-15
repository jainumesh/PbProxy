
#include <arpa/inet.h>
#include <errno.h>
#include <libgen.h>
#include <netdb.h>
#include <resolv.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <wait.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <fcntl.h>
#include <pthread.h>
#define ERR_RETURN -1

#define BUF_SIZE 1024

struct ctr_state {
    unsigned char ivec[AES_BLOCK_SIZE];  
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
}state;


int server_sock, client_sock, remote_sock;
char *destination_ip;
int local_port = 0;
int destination_port = 0;
unsigned char isClientMode= 1;
unsigned char*    key;

char msg_out[BUF_SIZE];
char msg_in[BUF_SIZE];
unsigned char iv[AES_BLOCK_SIZE];
AES_KEY aes_key;

char* read_file(const char* filename);
int create_socket(int port);
void server_loop(void);
void client_loop();
void handle_client(int client_sock, struct sockaddr_in client_addr);
void handle_server();
void forward_data_client(int destination_sock);
void forward_data_server(int source_sock, int destination_sock);
int parse_cmd_inputs(int argc, char *argv[]);
int init_ctr( );

char* read_file(const char* filename) {
	char *buffer = 0;
	long length;
	FILE *f = fopen (filename, "rb");
	
	if (f) {
		fseek (f, 0, SEEK_END);
		length = ftell (f);
		fseek (f, 0, SEEK_SET);
		buffer = malloc (length);
		if (buffer)
			fread (buffer, 1, length, f);
		fclose (f);
	} else{
		fprintf(stderr,"keyfile is invalid\n");
		//buffer = filename;
	}
	return buffer;
}


int main(int argc, char *argv[]) {

    parse_cmd_inputs(argc, argv);

    if (destination_ip == NULL || destination_port < 0 || local_port < 0) {
        printf("Syntax: pbproxy [-k <mykey>] [-l <local port #>, (reverse proxy mode)] <destination IP>  <Destination Port> \n" );
        return ERR_RETURN;
    }

        if(!isClientMode){
            if ((server_sock = create_socket(local_port)) < 0) { // start the server
                printf("Cannot run server error is [%d]",server_sock);
                return server_sock;
            }
            server_loop();
        }
        else{
            client_loop();
        }
    return 0;
}

/* Parse command line inputs */
int parse_cmd_inputs(int argc, char *argv[]) {

    int counter_i = 1;
	char * key_file = NULL;
/* we only support '-k' and '-l'  */
    while(argc>counter_i)
    {
        if(argv[counter_i][0] == '-'){
            
            switch(argv[counter_i][1]){
                case 'l':
                    local_port = atoi(argv[counter_i+1]);
                    isClientMode = 0;
                    break;
                case 'k':
                    key_file = argv[counter_i+1];
					key = read_file(key_file);
					if(*key == 0)
					key = key_file;
                    break;
                default:
                    printf("unsupported input\n");
                    return ERR_RETURN;
                }
            counter_i+=2;
        }else{
        destination_ip = argv[counter_i++];
        destination_port = atoi(argv[counter_i++]);
        break;
        }
    }
}

/* Create server socket */
int create_socket(int port) {
    int server_sock, optval;
    struct sockaddr_in server_addr;

    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return ERR_RETURN;
    }

    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        return ERR_RETURN;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
        return ERR_RETURN;
    }

    if (listen(server_sock, 20) < 0) {
        return ERR_RETURN;
    }

    return server_sock;
}


/* Main server loop */
void server_loop(void) {
    struct sockaddr_in client_addr;
    int addrlen = sizeof(client_addr);

    while (1) {
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &addrlen);
        handle_client(client_sock, client_addr);
        close(client_sock);
    }
	
}
void client_loop() {
    handle_server();
}
int init_ctr()
{
    state.num = 0;
    memset(state.ecount, 0, 16);
    memset(state.ivec + 8, 0, 8);
    memcpy(state.ivec, iv, 8);
}

/* Handle client connection */
void handle_client(int client_sock, struct sockaddr_in client_addr)
{
    if ((remote_sock = create_connection()) < 0) {
        printf("Cannot connect to host");
        return;
    }
    
    forward_data_server(client_sock, remote_sock);

    close(remote_sock);
    close(client_sock);
}
void handle_server()
{

    if ((remote_sock = create_connection()) < 0) {
        printf("Cannot connect to host");
        return;
    }

    
    forward_data_client(remote_sock);


}
void forward_data_server(int source_sock, int destination_sock) {
    
    int n, i,flags;
    unsigned char recvbytes =0;
    while(1){
	recvbytes = 1;	
    n = read(source_sock, msg_in, BUF_SIZE);
    if(n<8){
		fprintf(stderr, "Fuck me. less than 8 bytes[%d]\n",n);
		return ;
	}
    //fprintf(stderr, "Encrypted  string:[%s] size of n [%d].\n",msg_in,n);
    memcpy(iv,msg_in,8);
    //fprintf(stderr, "iv:[%s] .\n",iv);
    
    init_ctr();
    AES_set_encrypt_key(key, 128, &aes_key);
    AES_ctr128_encrypt(msg_in+8, msg_out, n-8, &aes_key, state.ivec, state.ecount, &state.num);
    i = write(destination_sock, msg_out, n-8);
    if(i != n-8)
		fprintf(stderr,"data 1left in buffer\n");
    n = read(destination_sock, msg_in, BUF_SIZE);
    if(n>0){
		//fprintf(stderr,"data 2left in buffer[%d]\n",n);
		AES_ctr128_encrypt(msg_in, msg_out, n, &aes_key, state.ivec, state.ecount, &state.num);
		write(source_sock, msg_out, n);
	}
	flags =fcntl(destination_sock,F_GETFL,O_NDELAY);
	//fcntl(destination_sock,F_SETFL,flags|O_NDELAY);
    //fprintf(stderr, "Decrypted  string:[%s] .\n",msg_out);
    while(1){
    /*send the 8 bit iv to remote party as 1st packet*/
    while ((n = read(source_sock, msg_in, BUF_SIZE)) > 0) { // read data from input socket
        /*Encrypt and sends*/
        AES_ctr128_encrypt(msg_in, msg_out, n, &aes_key, state.ivec, state.ecount, &state.num);
		//fprintf(stderr, "sending back to server:[%s] .\n",msg_out);
            if ((i=write(destination_sock, msg_out, n)) == -1) {
                fprintf (stderr,"send failed");
                exit(0);
            }
			memset(msg_in,0,BUF_SIZE);
			memset(msg_out,0,BUF_SIZE);	
			if(i != n)
				fprintf(stderr,"data left in buffer\n");
            if (n < BUF_SIZE){
				//fprintf (stderr,"n< BUF_SIZE[%d]",n);
                break;
			}
    }

    while((n = read(destination_sock, msg_in, BUF_SIZE))>0){
        AES_ctr128_encrypt(msg_in, msg_out, n, &aes_key, state.ivec, state.ecount, &state.num);
        write(source_sock, msg_out, n);
		if(recvbytes==0 && n ==0)
			recvbytes = 1;
		if (n < BUF_SIZE){
			//fprintf (stderr,"n< BUF_SIZE[%d]",n);
            break;
			}

    }
  
    }

        close(destination_sock);
        close(source_sock);
    }
}

void forward_data_client(int destination_sock) {
    int n, i;

    if (AES_set_encrypt_key(key, 128, &aes_key) < 0) {
        fprintf(stderr, "Set encryption key error!\n");
        exit(1);
    }
    if(!RAND_bytes(iv, 8)) {
        fprintf(stderr, "Error generating random bytes.\n");
        exit(1);
    }
    fcntl(STDIN_FILENO,F_SETFL,O_NONBLOCK);
    fcntl(destination_sock,F_SETFL,O_NONBLOCK);
    //fprintf(stderr, "RAND_bytes:[%s] .\n",iv);
    n = read(STDIN_FILENO, msg_in, BUF_SIZE);
    memcpy(msg_out, iv, 8);
    init_ctr();
    //fprintf(stderr, "Plain string:[%s] .\n",msg_in);

    AES_ctr128_encrypt(msg_in, msg_out+8, n, &aes_key, state.ivec, state.ecount, &state.num);
    if ((n = write(destination_sock, msg_out, n+8)) < 0){
        fprintf (stderr,"send failed");
        exit(0);
    }
    //fprintf(stderr, "Encrypted  string:[%s] .\n",msg_out);
    n = read(destination_sock, msg_in, BUF_SIZE);
    if(n>0){
		AES_ctr128_encrypt(msg_in, msg_out, n, &aes_key, state.ivec, state.ecount, &state.num);
		n = write(STDOUT_FILENO, msg_out, n);
	}

    while(1) {
		    //fprintf(stderr, "1st while encountered:[%s] .\n",msg_out);
            //fflush(STDIN_FILENO);    
        while ((n = read(STDIN_FILENO, msg_in, BUF_SIZE)) > 0) {
		    //fprintf(stderr, "2nd while encountered:[%s] .\n",msg_in);
            AES_ctr128_encrypt(msg_in, msg_out, n, &aes_key, state.ivec, state.ecount, &state.num);
            //fprintf(stderr, "Then %d bytes encrypted message\n", n);
            if ((n=write(destination_sock, msg_out, n) )== -1) {
                fprintf (stderr,"send failed");
                exit(0);
            }
            if (n < BUF_SIZE){
				//fprintf (stderr,"n< BUF_SIZE[%d]",n);
                break;
			}
               
        }
        
        while ((n = read(destination_sock, msg_in, BUF_SIZE)) > 0) {
		    //fprintf(stderr, "3rd while encountered:[%s] .\n",msg_in);
            AES_ctr128_encrypt(msg_in, msg_out, n, &aes_key, state.ivec, state.ecount, &state.num);
            n =write(STDOUT_FILENO, msg_out, n);
            if (n < BUF_SIZE){
				//fprintf (stderr,"n< BUF_SIZE[%d]",n);
                break;
			}
        }
    }
}


/* Create client connection */
int create_connection() {
    struct sockaddr_in server_addr;
    struct hostent *server;
    int sock,flags;
	struct timeval tv;
	int timeout = 0;
	tv.tv_sec =500;
	tv.tv_usec =0;
	
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return ERR_RETURN;
    }

    if ((server = gethostbyname(destination_ip)) == NULL) {
        errno = EFAULT;
        return ERR_RETURN;
    }
    

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(destination_port);
	/*if(setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,(char*)&tv, sizeof(tv))){
		fprintf(stderr,"setsockopt failed\n");
		return ERR_RETURN;
	}*/
    if (connect(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        return ERR_RETURN;
    }
	flags =fcntl(sock,F_GETFL,O_NDELAY);
	//fcntl(sock,F_SETFL,flags|O_NDELAY);

    return sock;
}



