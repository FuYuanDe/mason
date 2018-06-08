package main

/*
#cgo LDFLAGS: -L./ -lbfdd
#cgo CFLAGS: -I./
#include "bfdd.h"

void bfdLogCallback(char *val);
void bfdCallback(BFD_RSP *val);

void logCallOnMeGo_cgo(char *val)
{
	bfdLogCallback(val);
}

void callOnMeGo_cgo(BFD_RSP *val)
{
    bfdCallback(val);
}
*/
import "C"
