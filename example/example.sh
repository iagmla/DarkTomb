#!/bin/bash

tomb akms-cbc -e msg b1 test.pk test.sk && tomb akms-cbc -d b1 b2 test.pk test.sk
