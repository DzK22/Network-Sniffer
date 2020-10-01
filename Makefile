CC = gcc -g
CFLAGS = -lpcap -Wall -Werror -Wextra
EXEC = main
SRC_DIR = src/
OBJ_DIR = obj/
HD_DIR = headers/

$(EXEC): $(OBJ_DIR)$(EXEC).o
	$(CC) -o $(EXEC) $^ $(CFLAGS)

$(OBJ_DIR)$(EXEC).o: $(SRC_DIR)$(EXEC).c
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv $(EXEC).o $(OBJ_DIR)

$(OBJ_DIR)analyseur.o: $(SRC_DIR)analyseur.c
	$(CC) -c $< $(CFLAGS)
	mkdir -p $(OBJ_DIR)
	mv analyseur.o $(OBJ_DIR)

clean:
	rm -rf $(OBJ_DIR) $(EXEC) $(DOC_DIR)
