#pragma once
#include <stdio.h>
#include <Windows.h>
#include <string>
#include <iostream>
#include <winternl.h>

#define CHECK_POINTER_NULL(p, retval) if(NULL == p){return retval;}
#define CHECK_POINTER_NULL_VOID(p) if(NULL == p){return;}