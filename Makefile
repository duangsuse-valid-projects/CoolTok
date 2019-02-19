CFLAGS := -m32 -Wall -std=c99 -O3 -fno-stack-protector

cooltok: base64.o md5.o asm.o main.c
	$(CC) $(CFLAGS) $^ -o $@

rebuild: clean cooltok

asm.o: asm.s
	nasm -felf32 $^ -o $@

md5.o: md5.c
base64.o: base64.c

.PHONY: clean

clean:
	$(RM) cooltok md5.o base64.o asm.o
