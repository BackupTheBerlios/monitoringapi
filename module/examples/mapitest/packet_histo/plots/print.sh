# File   : print.sh
# AYTHOR : Konstantinos Xinidis
# EMAIL  : xinidis@csd.uoc.gr
# Copyright (c) 2002 

INPUT_FILE=$1
OUTPUT_FILE="/tmp/$1.ps"
TMP_FILE="/tmp/tmp.txt"

CMD1="set output \"$OUTPUT_FILE\""
CMD2="set terminal postscript color \"Helvetica\" 12"

rm -f $TMP_FILE &&
echo -e $CMD1 '\n' $CMD2 >> $TMP_FILE &&
cat $INPUT_FILE >> $TMP_FILE &&
cat $TMP_FILE |
gnuplot &&
rm -f $TMP_FILE 
