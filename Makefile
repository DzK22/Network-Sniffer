CC = gcc -g
CFLAGS = -lpcap -Wall -Werror -Wextra
EXEC = main
SRC_DIR = src/
OBJ_DIR = obj/
HD_DIR = headers/

$(EXEC): $(OBJ_DIR)$(EXEC).o $(OBJ_DIR)liaison.o $(OBJ_DIR)analyseur.o $(OBJ_DIR)network.o $(OBJ_DIR)transport.o $(OBJ_DIR)application.o
	$(CC) -o $(EXEC) $^ $(CFLAGS)

$(OBJ_DIR)$(EXEC).o: $(SRC_DIR)$(EXEC).c $(HD_DIR)analyseur.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv $(EXEC).o $(OBJ_DIR)

$(OBJ_DIR)liaison.o: $(SRC_DIR)liaison.c $(HD_DIR)liaison.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv liaison.o $(OBJ_DIR)

$(OBJ_DIR)network.o: $(SRC_DIR)network.c $(HD_DIR)network.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv network.o $(OBJ_DIR)

$(OBJ_DIR)transport.o: $(SRC_DIR)transport.c $(HD_DIR)transport.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv transport.o $(OBJ_DIR)

$(OBJ_DIR)application.o: $(SRC_DIR)application.c $(HD_DIR)application.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv application.o $(OBJ_DIR)

$(OBJ_DIR)analyseur.o: $(SRC_DIR)analyseur.c $(HD_DIR)analyseur.h
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv analyseur.o $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) $(EXEC) $(DOC_DIR)
