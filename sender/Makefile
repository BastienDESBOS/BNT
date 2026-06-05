# Sender SV temps réel pour le TNB (formats 6I3U et 4I4U).
# Dérivé de insatomcat/po (svgenerator/rt_sender.c) + option --format.

CC ?= cc
CFLAGS ?= -O2 -Wall

rt_sender: rt_sender.c
	$(CC) $(CFLAGS) -o rt_sender rt_sender.c -lm

clean:
	rm -f rt_sender

.PHONY: clean
