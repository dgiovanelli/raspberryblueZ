LDLIBS=-lbluetooth

all: scan advertise

advertise: advertise.c

scan: scan.c

clean:
	rm -f scan
	rm -f advertise
