#!/bin/bash

echo Which is the executable ? 
read EXEC
echo How many processes should i create ? 
read HOWMANY

for n in `seq 1 $HOWMANY`;	\
do	\
	echo $EXEC;	\
	$EXEC&	\
done
