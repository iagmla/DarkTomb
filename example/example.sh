#!/bin/bash

tomb -e msg msg.enc hello.pk test.sk && tomb -d msg.enc msg.dec test.pk hello.sk
