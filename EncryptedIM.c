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
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#define PORTNO 9879
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

  unsigned char *HM_DAT;// will hold out HMAC and data
 
  unsigned char *enc_out; //will hold encrypted data
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
      //printf("bytes read: %d\n",bytes_read);

      if( bytes_read > 0){

      /* Generate IV here */
	memset(IV,0x0,AES_BLOCK_SIZE);
	RAND_bytes(IV, AES_BLOCK_SIZE); // IV now holds our init vector of 16 bytes
 
      /* Generate HMAC here using K2 and data read */
      unsigned char *HMAC_K2;
      //memset(HMAC_K2,0x0,20);

      HMAC_K2 = HMAC(EVP_sha1(), K2, 16, buf, bytes_read, NULL, NULL);
      //hex_print(buf,bytes_read);
      //hex_print(HMAC_K2,20);
     

      /* Concat HMAC with data read */

      /* Encrypt HMAC + data read Here */ 
      HM_DAT = (unsigned char *) malloc(20+bytes_read); //Allocate memory for HMAC + data
      memset(HM_DAT, 0, 20+bytes_read); //zero it out
      memcpy(HM_DAT,HMAC_K2,20);
      memcpy(HM_DAT+20,buf,bytes_read);
    
      // buffers for encryption
      encslength = ((20 + bytes_read + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE; //set encryption length
      //unsigned char enc_out[encslength];
      enc_out = (unsigned char *) malloc(encslength); //Allocate memory for encrypted data
      memset(enc_out, 0, encslength); //zero it out

      

      message = (unsigned char*) malloc(AES_BLOCK_SIZE + encslength); //allocate memory for overall message

      memcpy(message,IV,16); //copy our IV into overall message

      // Set up the key and encrypt
      AES_KEY enc_key;
      AES_set_encrypt_key(K1, 128, &enc_key);

      AES_cbc_encrypt(HM_DAT, enc_out, 20+bytes_read, &enc_key, IV, AES_ENCRYPT);
      //hex_print(enc_out,encslength);//print out encrypted generated


      /* Concat IV and Encrypted Data Here */
      memcpy(message+AES_BLOCK_SIZE,enc_out,encslength); //add encrypted data to overall message	


      }
       
      
      
      //Free our dynamically allocated memory
      if( bytes_read > 0){ //quick check so we avoid dumps
      /* echo it back buffer is message and length is IV length + length of encrypted data*/
      write(conn_sock,message,AES_BLOCK_SIZE + encslength);
      free(message);
      free(enc_out);
      free(HM_DAT);
      }else{
        break;

      }
    }
    if (FD_ISSET(conn_sock,&set)) {
      /* process data from the connection */
      bytes_read = read(conn_sock,buf,BUFSIZE);
      //printf("bytes read rec: %d\n",bytes_read);
      unsigned char *dec_out;

      if (bytes_read == 0) {
	/* end-of-file! */
	break;
      }
      else{

      /*Get IV (first 16 bytes) from received data */

      memset(IV,0x0,AES_BLOCK_SIZE);
      memcpy(IV, &buf[0], AES_BLOCK_SIZE); //got our IV
      //hex_print(buf,BUFSIZE);

      //Allocate some memory for encrypted portion of our received data
      unsigned char to_dec[bytes_read - AES_BLOCK_SIZE];
      memset(to_dec, 0, sizeof(to_dec));//zero it out

      //Get encrypted portion
      memcpy(to_dec, &buf[AES_BLOCK_SIZE], bytes_read - AES_BLOCK_SIZE);
      
      //hex_print(to_dec,bytes_read - AES_BLOCK_SIZE);//print out encrypted recieved

      //Allocate memory for where we will store our decryption
      dec_out = (unsigned char *) malloc(bytes_read - AES_BLOCK_SIZE);
      memset(dec_out, 0, sizeof(dec_out)); //zero it out
      
      //Set up the key and decrypt 
      AES_KEY dec_key;
      AES_set_decrypt_key(K1, 128, &dec_key);
      /*Using IV and K1 decrypt rest of the message store into dec_out */
      AES_cbc_encrypt(to_dec, dec_out, bytes_read - AES_BLOCK_SIZE, &dec_key, IV, AES_DECRYPT);

      //printf(" dec:%s\n",dec_out);//it does decrypt! We now have the decrypted data!

      unsigned int message_size = bytes_read - 36;//( ( (bytes_read - AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE) - 20 - AES_BLOCK_SIZE;

      /* Seperate Decrypted code to get HMAC and decrypted data */

      unsigned char sent_hmac[20];
      unsigned char *HMAC_K2;
      memcpy(sent_hmac, &dec_out[0], 20);
      hex_print(sent_hmac,20);
      message = (unsigned char *) malloc(message_size);
      memcpy(message,&dec_out[20],message_size);

      HMAC_K2 = HMAC(EVP_sha1(), K2, 16, message, message_size, NULL, NULL);
      //hex_print(message, message_size);
      //hex_print(HMAC_K2,20);

      /*if(memcmp(HMAC_K2,sent_hmac, 20) != 0){
 	printf("Error HMAC was incorrect!\n");
	exit(1);
      }*/

      /* Regenerate HMAC using K2 and decrypted data and compare to decrypted HMAC, if good HMAC then do nohing 
	(if bad HMAC msg and quit)*/

      
      /* set data to be printed in a buffer */




      }
      write(STDOUT_FILENO,message,bytes_read - AES_BLOCK_SIZE - 20); /* write received data to stdout CHANGE BUFFER AND BYTES READ*/
      free(dec_out);
      free(message);
    }
  }

  close( conn_sock );
  close( sock );
  return 0;			/* all's well that ends well */
}
