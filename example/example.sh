#!/bin/bash

tomb akms-cbc -e msg msg.enc hello.pk test.sk && tomb akms-cbc -d msg.enc msg.dec test.pk hello.sk
