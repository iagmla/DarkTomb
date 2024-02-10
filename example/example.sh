#!/bin/bash

tomb akms-cbc -e msg b1 hello.pk test.sk && tomb akms-cbc -d b1 b2 test.pk hello.sk
