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


#define PORTNO 9999
#define BUFSIZE 1024

int sock = -1;
int conn_sock = -1;


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
  const char *usage = "Usage: UnencryptedIM -s|-c hostname";
  if (argc < 2 ) {
    printf( "%s\n\n", usage );
    exit(1);
  }
  if( strcmp(argv[1],"-s") == 0 ) {
    return NULL;		/* start in server mode */
  } else if ((argc != 3) || (strcmp(argv[1],"-c") != 0)) {
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




int main( int argc, char *argv[] )
{
  char *client;
  char buf[BUFSIZE];
  int bytes_read;
  fd_set set;
  int nfds;

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
  } else {
    /* we are the client, so connect to the server */
    conn_sock = connect_to_client(sock,client);
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
      write(conn_sock,buf,bytes_read); /* echo it back */
    }
    if (FD_ISSET(conn_sock,&set)) {
      /* process data from the connection */
      bytes_read = read(conn_sock,buf,BUFSIZE);
      if (bytes_read == 0) {
	/* end-of-file! */
	break;
      }
      write(STDOUT_FILENO,buf,bytes_read); /* write received data to stdout */
    }
  }

  close( conn_sock );
  close( sock );
  return 0;			/* all's well that ends well */
}
