#! /usr/bin/make

# Designed to be run one level up
lightningd_hsm-wrongdir:
	$(MAKE) -C .. lightningd_hsm-all

default: lightningd_hsm-all

# Clients use this:
LIGHTNINGD_HSM_CLIENT_HEADERS := lightningd_hsm/client.h
LIGHTNINGD_HSM_CLIENT_SRC := lightningd_hsm/client.c lightningd_hsm/gen_hsm_client_wire.c
LIGHTNINGD_HSM_CLIENT_OBJS := $(LIGHTNINGD_HSM_CLIENT_SRC:.c=.o)

# Control daemon uses this:
LIGHTNINGD_HSM_CONTROL_HEADERS := lightningd_hsm/gen_hsm_control_wire.h
LIGHTNINGD_HSM_CONTROL_SRC := lightningd_hsm/gen_hsm_control_wire.c
LIGHTNINGD_HSM_CONTROL_OBJS := $(LIGHTNINGD_HSM_CONTROL_SRC:.c=.o)

# lightningd_hsm needs these:
LIGHTNINGD_HSM_HEADERS := lightningd_hsm/gen_hsm_client_wire.h	\
	lightningd_hsm/gen_hsm_control_wire.h			\
	lightningd_hsm/gen_hsm_status_wire.h
LIGHTNINGD_HSM_SRC := lightningd_hsm/hsm.c	\
	lightningd_hsm/gen_hsm_client_wire.c	\
	lightningd_hsm/gen_hsm_control_wire.c	\
	lightningd_hsm/gen_hsm_status_wire.c
LIGHTNINGD_HSM_OBJS := $(LIGHTNINGD_HSM_SRC:.c=.o)

# For checking
LIGHTNINGD_HSM_ALLSRC_NOGEN := $(filter-out lightningd_hsm/gen_%, $(LIGHTNINGD_HSM_CLIENT_SRC) $(LIGHTNINGD_HSM_SRC))
LIGHTNINGD_HSM_ALLHEADERS_NOGEN := $(filter-out lightningd_hsm/gen_%, $(LIGHTNINGD_HSM_CLIENT_HEADERS) $(LIGHTNINGD_HSM_HEADERS))

lightningd_hsm-all: lightningd_hsm/lightningd_hsm $(LIGHTNINGD_HSM_CLIENT_OBJS)

lightningd_hsm/gen_hsm_client_wire.h: $(WIRE_GEN) lightningd_hsm/hsm_client_wire_csv
	$(WIRE_GEN) --header $@ hsm_client_wire_type < lightningd_hsm/hsm_client_wire_csv > $@

lightningd_hsm/gen_hsm_client_wire.c: $(WIRE_GEN) lightningd_hsm/hsm_client_wire_csv
	$(WIRE_GEN) ${@:.c=.h} hsm_client_wire_type< lightningd_hsm/hsm_client_wire_csv > $@

lightningd_hsm/gen_hsm_control_wire.h: $(WIRE_GEN) lightningd_hsm/hsm_control_wire_csv
	$(WIRE_GEN) --header $@ hsm_control_wire_type < lightningd_hsm/hsm_control_wire_csv > $@

lightningd_hsm/gen_hsm_control_wire.c: $(WIRE_GEN) lightningd_hsm/hsm_control_wire_csv
	$(WIRE_GEN) ${@:.c=.h} hsm_control_wire_type < lightningd_hsm/hsm_control_wire_csv > $@

lightningd_hsm/gen_hsm_status_wire.h: $(WIRE_GEN) lightningd_hsm/hsm_status_wire_csv
	$(WIRE_GEN) --header $@ hsm_status_wire_type < lightningd_hsm/hsm_status_wire_csv > $@

lightningd_hsm/gen_hsm_status_wire.c: $(WIRE_GEN) lightningd_hsm/hsm_status_wire_csv
	$(WIRE_GEN) ${@:.c=.h} hsm_status_wire_type < lightningd_hsm/hsm_status_wire_csv > $@

$(LIGHTNINGD_HSM_OBJS) $(LIGHTNINGD_HSM_CLIENT_OBJS): $(LIGHTNINGD_HSM_HEADERS) $(LIGHTNINGD_HSM_GEN_HEADERS)

lightningd_hsm/lightningd_hsm: $(LIGHTNINGD_HSM_OBJS)

check-source: $(LIGHTNINGD_HSM_ALLSRC_NOGEN:%=check-src-include-order/%) $(LIGHTNINGD_HSM_ALLHEADERS_NOGEN:%=check-hdr-include-order/%)
check-source-bolt: $(LIGHTNINGD_HSM_SRC:%=bolt-check/%) $(LIGHTNINGD_HSM_HEADERS:%=bolt-check/%)

clean: lightningd_hsm-clean

lightningd_hsm-clean:
	$(RM) $(LIGHTNINGD_HSM_OBJS) gen_*

-include lightningd_hsm/test/Makefile 
