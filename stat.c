



#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <semaphore.h>
#include <sys/mman.h>

#include <ctype.h>
#include <regex.h>

#include <sys/vfs.h>
#include <sys/statvfs.h>

char *comma_snprintf(char *buffer, int size, const char *format, ...)
{
    register unsigned int len, i;
    char buf[1024], *src, *dest;
    register size_t vsize = size > (1024 - 1) ? 1024 - 1 : size;
    va_list ap;

    va_start(ap, format);
    len = vsnprintf((char *)buf, vsize, format, ap);
    va_end(ap);

    if (len)
    {
       src = buf + strlen((const char *)buf);
       dest = buffer + vsize;
       *dest = '\0';
       for (i=0; (i < strlen((const char *)buf)) &&
            (dest >= buffer) && (src >= buf); i++)
       {
          if (i && !(i % 3))
             *--dest = ',';
          *--dest = *--src;
       }
       return (char *)dest;
    }
    return (char *)"";
}

// scaled chars for kilobyte, megabyte, gigabyte, terabyte,
// petabyte, exabyte, zettabyte, and yottabyte
char scale_chars[]={ 'K','M','G','T','P','E','Z','Y', };
char *comma_snprintf_scaled(char *buffer, int size, const char *format, unsigned long long value, unsigned int width)
{
    register unsigned int len, i;
    char buf[1024], *src, *dest, ch = '\0';
    register size_t vsize = size > (1024 - 1) ? 1024 - 1 : size;

    // NOTE:  the width specified should be -4 less than display size
    len = snprintf((char *)buf, vsize, format, value);
    if (len)
    {
       int adjlen = len / 3;
       for (i=0; i < sizeof(scale_chars) && ((len + adjlen) > width); i++) {
           ch = scale_chars[i];
           value /= 1000;
           len = snprintf((char *)buf, vsize, format, value);
           adjlen = len / 3;
       }

       src = buf + strlen((const char *)buf);
       dest = buffer + vsize;
       *dest = '\0';
       if (ch) {
          *--dest = 'b';
          *--dest = ch;
          *--dest = ' ';
       }

       register unsigned int buflen = strlen((const char *)buf);
       for (i=0; (i < buflen) && (dest >= buffer) && (src >= buf); i++)
       {
          if (i && !(i % 3))
             *--dest = ',';
          *--dest = *--src;
       }
       return (char *)dest;

    }
    return (char *)"";
}

char mysql_datadir[4096+1] = { "/var/lib/mysql" };

unsigned long long mysql_free_size(void)
{
	char buffer[1024];
	FILE *fp;
	unsigned long long len = 0, flag = 0;

	fp = fopen("/etc/my.cnf", "rb");
	while (fp && !feof(fp))
	{
		if (fgets(buffer, 1024, fp)) 
		{
			int count;
			char temp[1024], *src, *dest;
			temp[0] = '\0';
			count = 0;
			src = buffer;
			dest = temp;

			// strip out all spaces and punc characters
			while (*src) {
				if (++count > 1024)
					break;
				if ((*src == '\n') || (*src == ' ') || (*src == '\t') ||
					 (*src == '\r') || (*src == ';') || (*src == ',')) {
					src++;
				}
				else				
					*dest++ = *src++;
			}
			*dest = '\0';

			// skip empty lines
			if (!temp[0])
				continue;

			// skip comments
			if (!strncasecmp(temp, "#", 1))
				continue;

			if (!strncasecmp(temp, "[mysqld]", 8)) {
				flag++;
			}
			else if (!strncasecmp(temp, "datadir=", 8) && flag) {
				flag = 0;
				strncpy(mysql_datadir, &temp[8], 4096+1);
    				struct statvfs stat;
				if (!statvfs(mysql_datadir, &stat)) {
					len = (unsigned long long)stat.f_bavail * stat.f_frsize;
					fclose(fp);
					return len;
				}
			}
			else if (!strncasecmp(temp, "[", 1)) {
				// if new section, clear mysqld flag
				flag = 0;
			}
		}
	}
	if (fp) {
		fclose(fp);
	}

	struct statvfs stat;
	if (!statvfs(mysql_datadir, &stat)) {
		len = (unsigned long long)stat.f_bavail * stat.f_frsize;
		return len;
	}
	return len;

}

int main(int argc, char *argv[])
{
        unsigned long long len = mysql_free_size();
	char buf[1024];
	char *w = comma_snprintf_scaled(buf, sizeof(buf), "%llu", len, 20);
	printf("%s free size is %s bytes\n", mysql_datadir, w);
	return 0;
}

