
#!/bin/bash

VAR1=$(pgrep ipop)
VAR2=$(pgrep python)

#echo $VAR1
#echo $VAR2
ps aux | grep ipop
if [ -n "$VAR1" ]; then
   sudo kill $VAR1
fi
ps aux | grep python
if [ -n "$VAR2" ]; then
   sudo kill $VAR2
fi
echo
ps aux | grep ipop
ps aux | grep python

