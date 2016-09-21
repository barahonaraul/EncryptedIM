#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define PORTNO 9869
#define BUFSIZE 1024

int sock = -1;
int conn_sock = -1;

static void hex_print(const void* pv, size_t len)
{
    const unsigned char * p = (const unsigned char*)pv;
    if (NULL == pv)
        printf("NULL");
    else
    {
        size_t i = 0;
        for (; i<len;++i)
            printf("%02X ", *p++);
    }
    printf("\n");
}



/*
 * signal handler to catch CTRL-C and shut down things nicely
 */
void stop_and_exit( int signo )
{
  if( conn_sock != -1 ) {
    close( conn_sock );
  }
  if( sock != -1 ) {
    close(sock);
  }
  exit( 0 );
}


/*
 * returns the max of two ints
 */
int max(int a, int b)
{
  return (a > b)?a:b;
}


/*
 * Parses the command line.
 * exits on invalid command line
 * returns the client name if -c specified, otherwise returns NULL
 */ 
char *parse_command_line( int argc, char *argv[] )
{
  const char *usage = "Usage: UnencryptedIM -s|-c hostname [-confkey K1] [-authkey K2]";
  if (argc < 6 ) {
    printf( "%s\n\n", usage );
    exit(1);
  }
  if( strcmp(argv[1],"-s") == 0 ) {
    if ((strcmp(argv[2],"-confkey") != 0) || (strcmp(argv[4],"-authkey") != 0)){
        printf( "%s\n\n", usage ); 
        exit(1);
    }

    return NULL;		/* start in server mode */
  } else if ((argc != 7) || (strcmp(argv[1],"-c") != 0) || (strcmp(argv[3],"-confkey") != 0) || (strcmp(argv[5],"-authkey") != 0)) {
    printf( "%s\n\n", usage ); 
    exit(1);
  }
  return argv[2];
}


/**
 * connect to a client on host 'hostname'
 */
int connect_to_client( int sock, char *hostname )
{
  struct sockaddr_in serv_addr;
  struct hostent *remote;

  remote = gethostbyname(hostname);
  if (remote == NULL) {
    perror("gethostbyname");
    exit(1);
  }
  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  bcopy((char *)remote->h_addr, 
	(char *)&serv_addr.sin_addr.s_addr,
	remote->h_length);
  serv_addr.sin_port = htons(PORTNO);
  if (connect(sock,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) == -1) { 
    perror("connect");
    exit(1);
  }
  return sock;
}



/**
 * Wait for an incoming connection
 */
int wait_for_client( int sock )
{
  struct sockaddr_in serv_addr, cli_addr;
  socklen_t len;
  int newsockfd;

  bzero((char *) &serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(PORTNO);
  if (bind(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1)  {
    perror("bind");
    exit( 1 );
  }
  listen(sock,1);
  len = sizeof(struct sockaddr_in);
  newsockfd = accept(sock, (struct sockaddr *)&cli_addr, &len);
  if (newsockfd == -1)  {
    perror("accept");
    exit( 1 );
  }
  return newsockfd;
}

/* This function takes as input::
	temp: a 20 byte temporary unsigned char array that will hold whole hash
	str: the string we are trying to hash
   This function stores our 16byte hash value to::
	sha16b
*/
 
void SHA1_16BYTES(unsigned char *sha16b, unsigned char *temp, char *str){

    memset(temp, 0x0, SHA_DIGEST_LENGTH);

    SHA1((unsigned char *)str, strlen(str), temp);
    memcpy(sha16b, temp, SHA_DIGEST_LENGTH-4);

} 



int main( int argc, char *argv[] )
{
  char *client;
  char buf[BUFSIZE];
  int bytes_read;
  fd_set set;
  int nfds;
  unsigned char IV[AES_BLOCK_SIZE];
  unsigned char K1[16], K2[16];
  unsigned char temp[SHA_DIGEST_LENGTH];

      //Define a message pointer where all final data will be concatenated
      unsigned char *message;
  size_t encslength; //size of encryption buffer
  //unsigned char HMAC[];
	

  /* set up signal handler to deal with CTRL-C */
  signal( SIGINT, stop_and_exit );

  /* parse command line */
  client = parse_command_line(argc,argv); 

  /* create a socket */
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1) {
    perror("sock");
    return 1;
  }

  if (client == NULL) {
    /* if client is NULL, then we are the server, so wait for a new connection */
    conn_sock = wait_for_client(sock);

   /* Get HASH values for K1 and K2 here because arg index dependant on -s|-c */
   SHA1_16BYTES(K1, temp, argv[3]);
   SHA1_16BYTES(K2, temp, argv[5]);

  } else {
    /* we are the client, so connect to the server */
    conn_sock = connect_to_client(sock,client);

   /* Get HASH values for K1 and K2 here */
   SHA1_16BYTES(K1, temp, argv[4]);
   SHA1_16BYTES(K2, temp, argv[6]);

  }


  
  while( 1 ) {
    /* create our FDSET */
    FD_ZERO( &set );		/* zero it first */
    FD_SET( STDIN_FILENO, &set );	/* add in stdin */
    FD_SET( conn_sock, &set );	/* add in the network socket */
    nfds = max(STDIN_FILENO,conn_sock) + 1;

    /* here's where we block -- wait for something to happen */
    if (select(nfds,&set,NULL,NULL,NULL) == -1) {
      perror("select");
      exit(1);
    }

    /* consider the two cases -- input from stdin or from the network */
    if (FD_ISSET(STDIN_FILENO,&set)) {
      /* process data from stdin */
      bytes_read = read(STDIN_FILENO,buf,BUFSIZE);	
	printf("bytes read: %d\n",bytes_read);
      if( bytes_read > 0){

      /* Generate IV here */
	memset(IV,0x0,AES_BLOCK_SIZE);

	
	RAND_bytes(IV, AES_BLOCK_SIZE); // IV now holds our init vector of 16 bytes
 
      /* Generate HMAC here using K2 and data read */

      /* Concat HMAC with data read */

      /* Encrypt HMAC + data read Here */ 
	//Lets see if we can encrypt for now...
    
    // buffers for encryption
    encslength = ((bytes_read + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char enc_out[encslength];
    memset(enc_out, 0, sizeof(enc_out));

    message = (unsigned char*) malloc(AES_BLOCK_SIZE + encslength);
    printf("size of msg1:%ld\n",sizeof(message));
    memcpy(message,IV,16);

    // Set up the key and encrypt
    AES_KEY enc_key;
    AES_set_encrypt_key(K1, 128, &enc_key);

    AES_cbc_encrypt(buf, enc_out, bytes_read, &enc_key, IV, AES_ENCRYPT);

	

	//hex_print(message,encslength+16);
	memcpy(message+AES_BLOCK_SIZE,enc_out,encslength);
	
	//hex_print(message,encslength+16);

      /* Concat IV and Encrypted Data Here and get size of whole */
      
	


      }
      printf("size of msg2:%ld\n",sizeof(message));
      write(conn_sock,message,AES_BLOCK_SIZE + encslength); /* echo it back CHANGE BUFFER AND BYTES READ*/
      free(message);
    }
    if (FD_ISSET(conn_sock,&set)) {
      /* process data from the connection */
      bytes_read = read(conn_sock,buf,BUFSIZE);
      printf("bytes read rec: %d\n",bytes_read);
      unsigned char *dec_out;

      if (bytes_read == 0) {
	/* end-of-file! */
	break;
      }
      else{

      /*Get IV (first 16 bytes) from received data */

      memset(IV,0x0,AES_BLOCK_SIZE);
      memcpy(IV, &buf[0], AES_BLOCK_SIZE);
	//hex_print(buf,BUFSIZE);

      unsigned char to_dec[bytes_read - AES_BLOCK_SIZE];
      memset(to_dec, 0, sizeof(to_dec));
      printf("br-16:%d\n",bytes_read - AES_BLOCK_SIZE);
      memcpy(to_dec, &buf[AES_BLOCK_SIZE], bytes_read - AES_BLOCK_SIZE);
      //hex_print(to_dec,bytes_read - AES_BLOCK_SIZE);

      dec_out = (unsigned char *) malloc(bytes_read - AES_BLOCK_SIZE);
      memset(dec_out, 0, sizeof(dec_out));
      
      AES_KEY dec_key;
      AES_set_decrypt_key(K1, 128, &dec_key);
      AES_cbc_encrypt(to_dec, dec_out, bytes_read - AES_BLOCK_SIZE, &dec_key, IV, AES_DECRYPT);

      /*Using IV decrypt rest of the message */

      /* Seperate Decrypted code to get HMAC and decrypted data */

      /* Regenerate HMAC using K2 and decrypted data and compare to decrypted HMAC, if good HMAC then do nohing 
	(if bad HMAC msg and quit)*/

      
      /* set data to be printed in a buffer */




      }
      write(STDOUT_FILENO,dec_out,sizeof(dec_out)); /* write received data to stdout CHANGE BUFFER AND BYTES READ*/
      free(dec_out);
    }
  }

  close( conn_sock );
  close( sock );
  return 0;			/* all's well that ends well */
}
