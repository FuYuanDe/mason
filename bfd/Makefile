default:
	@/opt/toolchains/gcc-linaro-arm-linux-gnueabihf-4.9-2014.09_linux/bin/arm-linux-gnueabihf-gcc -c bfdd.c -lrt -lpthread -fPIC 
	@/opt/toolchains/gcc-linaro-arm-linux-gnueabihf-4.9-2014.09_linux/bin/arm-linux-gnueabihf-gcc -shared -o libbfdd.so bfdd.o -fPIC 	
	@cp libbfdd.so ../../../../sbc/lib/		
clean:
	@rm -rf bfdd.o libbfdd.so	
