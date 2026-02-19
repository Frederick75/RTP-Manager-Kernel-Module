CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra -pthread

all: rtp_app

rtp_app: rtp_app.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f rtp_app
