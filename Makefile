CC = gcc -g
CFLAGS = -lpcap -Wall -Werror -Wextra
EXEC = main
SRC_DIR = src/
OBJ_DIR = obj/
HD_DIR = headers/

$(EXEC): $(OBJ_DIR)$(EXEC).o $(OBJ_DIR)liaison.o $(OBJ_DIR)analyseur.o $(OBJ_DIR)network.o $(OBJ_DIR)ip.o $(OBJ_DIR)arp.o $(OBJ_DIR)transport.o $(OBJ_DIR)ospf.o $(OBJ_DIR)application.o $(OBJ_DIR)dns.o $(OBJ_DIR)transfer.o $(OBJ_DIR)dhcp.o $(OBJ_DIR)telnet.o
	$(CC) -o nSniffer $^ $(CFLAGS)

$(OBJ_DIR)$(EXEC).o: $(SRC_DIR)$(EXEC).c $(HD_DIR)analyseur.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv $(EXEC).o $(OBJ_DIR)

$(OBJ_DIR)liaison.o: $(SRC_DIR)liaison.c $(HD_DIR)liaison.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv liaison.o $(OBJ_DIR)

$(OBJ_DIR)network.o: $(SRC_DIR)network.c $(HD_DIR)network.h $(HD_DIR)ip.h $(HD_DIR)arp.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv network.o $(OBJ_DIR)

$(OBJ_DIR)ip.o: $(SRC_DIR)ip.c $(HD_DIR)ip.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv ip.o $(OBJ_DIR)

$(OBJ_DIR)arp.o: $(SRC_DIR)arp.c $(HD_DIR)arp.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv arp.o $(OBJ_DIR)

$(OBJ_DIR)transport.o: $(SRC_DIR)transport.c $(HD_DIR)transport.h $(HD_DIR)ospf.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv transport.o $(OBJ_DIR)

$(OBJ_DIR)ospf.o: $(SRC_DIR)ospf.c $(HD_DIR)ospf.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv ospf.o $(OBJ_DIR)

$(OBJ_DIR)application.o: $(SRC_DIR)application.c $(HD_DIR)application.h $(HD_DIR)dns.h $(HD_DIR)transfer.h $(HD_DIR)dhcp.h $(HD_DIR)telnet.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv application.o $(OBJ_DIR)

$(OBJ_DIR)dns.o: $(SRC_DIR)dns.c $(HD_DIR)dns.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv dns.o $(OBJ_DIR)

$(OBJ_DIR)telnet.o: $(SRC_DIR)telnet.c $(HD_DIR)telnet.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv telnet.o $(OBJ_DIR)

$(OBJ_DIR)transfer.o: $(SRC_DIR)transfer.c $(HD_DIR)transfer.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv transfer.o $(OBJ_DIR)

$(OBJ_DIR)dhcp.o: $(SRC_DIR)dhcp.c $(HD_DIR)dhcp.h $(HD_DIR)bootp.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv dhcp.o $(OBJ_DIR)

$(OBJ_DIR)analyseur.o: $(SRC_DIR)analyseur.c $(HD_DIR)analyseur.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv analyseur.o $(OBJ_DIR)


clean:
	rm -rf $(OBJ_DIR) nSniffer $(DOC_DIR)
