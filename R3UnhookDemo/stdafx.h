#pragma once
#include <stdio.h>
#include <Windows.h>
#include <string>
#include <iostream>

#define CHECK_POINTER_NULL(p, retval) if(NULL == p){return retval;}