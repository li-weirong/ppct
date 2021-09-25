privacyProgram=million
CILPATH=/root/obliv-c
REMOTE_HOST=localhost
CFLAGS=-DREMOTE_HOST=$(REMOTE_HOST) -O3  
./a.out: $(privacyProgram).oc $(privacyProgram).c 
	$(CILPATH)/_build/libobliv.a
	$(CILPATH)/bin/oblivcc 
	$(CFLAGS) $(privacyProgram).oc $(privacyProgram).c -lm
clean:
	rm -f a.out
clean-all:
	rm -f *.cil.c *.i *.o