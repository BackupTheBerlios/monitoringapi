# File   : printall.sh
# AYTHOR : Konstantinos Xinidis
# EMAIL  : xinidis@csd.uoc.gr
# Copyright (c) 2002 

OUTPUT_FILE="all.ps"
TMP_FILE="tmp.txt"

CMD1="set output \"$OUTPUT_FILE\""
CMD2="set terminal postscript landscape color solid \"Times-Roman\" 12"

rm -f $TMP_FILE &&
echo $CMD1 "\n" $CMD2 >> $TMP_FILE &&

for object in $@
do
	cat $object >> $TMP_FILE
	echo "clear" >> $TMP_FILE
	echo "reset" >> $TMP_FILE
done

cat $TMP_FILE |
gnuplot &&
rm -f $TMP_FILE 
