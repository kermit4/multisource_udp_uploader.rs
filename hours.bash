#!/bin/bash
echo $((`wc -l < worklog.txt ` / 60))
